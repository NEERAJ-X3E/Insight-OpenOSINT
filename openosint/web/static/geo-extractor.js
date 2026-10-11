/**
 * geo-extractor.js — per-tool geo-feature extraction from tool_result output.
 *
 * Parallel to entity-graph.js's normalizer registry, same shape: pure text
 * in, GeoJSON Feature array out, never throws. Tools with no geo output in
 * their formatted string simply have no entry here.
 *
 * search_gdelt_geo is the one entry that doesn't parse `[+]`-style lines —
 * its output carries the whole FeatureCollection in a fenced
 * ```geojson block (see openosint/tools/search_gdelt_geo.py), so its
 * extractor just pulls that block back out.
 */

function _point(lon, lat, properties = {}) {
  let finalLat = parseFloat(lat);
  let finalLon = parseFloat(lon);
  if (!Number.isFinite(finalLat) || !Number.isFinite(finalLon)) return null;
  // Auto-detect accidental lat/lon inversion (lat > 90 cannot be latitude)
  if (Math.abs(finalLat) > 90 && Math.abs(finalLon) <= 90) {
    const tmp = finalLat;
    finalLat = finalLon;
    finalLon = tmp;
  }
  if (finalLat < -90 || finalLat > 90 || finalLon < -180 || finalLon > 180) return null;
  return { type: 'Feature', geometry: { type: 'Point', coordinates: [finalLon, finalLat] }, properties };
}

function _val(text, prefixPattern) {
  const re = new RegExp(`${prefixPattern}\\s*(.+)$`, 'm');
  const m = re.exec(text);
  return m ? m[1].trim() : null;
}

const _REGISTRY = {

  /** search_ip output example:
   *   IP intelligence for '8.8.8.8':
   *   [+] Loc: 37.4056,-122.0775
   */
  search_ip(target, output) {
    const loc = _val(output, '\\[\\+\\] Loc:');
    if (!loc) return [];
    const [latStr, lonStr] = loc.split(',');
    const feature = _point(parseFloat(lonStr), parseFloat(latStr), { tool: 'search_ip', target, name: target });
    return feature ? [feature] : [];
  },

  /** search_ip2location output example:
   *   [IP2Location] Latitude: 37.4056
   *   [IP2Location] Longitude: -122.0775
   */
  search_ip2location(target, output) {
    const lat = parseFloat(_val(output, '\\[IP2Location\\] Latitude:'));
    const lon = parseFloat(_val(output, '\\[IP2Location\\] Longitude:'));
    const feature = _point(lon, lat, { tool: 'search_ip2location', target, name: target });
    return feature ? [feature] : [];
  },

  /** search_gdelt_geo: raw GeoJSON FeatureCollection in a fenced block. */
  search_gdelt_geo(_target, output) {
    const m = /```geojson\n([\s\S]*?)```/.exec(output);
    if (!m) return [];
    try {
      const fc = JSON.parse(m[1]);
      return Array.isArray(fc.features) ? fc.features : [];
    } catch {
      return [];
    }
  },
};

const _GEOJSON_FENCE_RE = /```geojson\n([\s\S]*?)```/;

/**
 * Split a tool result into [textForModel, rawGeojsonOrNull].
 *
 * Mirrors openosint/tools/search_gdelt_geo.py's split_geojson_fence(). The
 * fence exists so the browser can pull the raw FeatureCollection out over
 * SSE — the model has no use for raw coordinates, and every provider
 * call site resends the whole message list on every subsequent round of
 * the investigation, so an unstripped fence costs real tokens repeatedly.
 * Every model-bound call site (agent-loop.js's appendToolResult) must call
 * this; the SSE tool_result event itself keeps the original string.
 *
 * Returns [output, null] unchanged when no fence is present.
 */
export function splitGeojsonFence(output) {
  const m = _GEOJSON_FENCE_RE.exec(output || '');
  if (!m) return [output, null];

  const geojson = m[1];
  let featureCount = 0;
  try {
    featureCount = JSON.parse(geojson).features?.length || 0;
  } catch {
    featureCount = 0;
  }

  const text = output.slice(0, m.index).trimEnd() + `\n\n[${featureCount} geo point(s) → globe]`;
  return [text, geojson];
}

/**
 * Extract GeoJSON Point features from a tool result.
 * Never throws — any parse failure returns an empty array.
 */
export function extractGeoFeatures(toolName, target, output) {
  const text = output || '';

  // 1. If tool result has a fenced geojson block, extract and validate features
  const m = _GEOJSON_FENCE_RE.exec(text);
  if (m) {
    try {
      const fc = JSON.parse(m[1]);
      if (Array.isArray(fc.features) && fc.features.length) {
        const valid = fc.features.filter(f => f?.geometry?.type === 'Point' && Array.isArray(f.geometry.coordinates));
        if (valid.length) return valid;
      }
    } catch {}
  }

  // 2. Specific registered extractor
  const extractor = _REGISTRY[toolName];
  if (extractor) {
    try {
      const res = extractor(target, text);
      if (Array.isArray(res) && res.length) return res;
    } catch {}
  }

  // 3. Fallback: parse [+] Loc: lat,lon or Coordinates: lat,lon
  const locMatch = text.match(/\[\+\]\s*(?:Loc|Coordinates?):\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)/i)
    || text.match(/(?:Loc|Coordinates?):\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)/i);
  if (locMatch) {
    const lat = parseFloat(locMatch[1]);
    const lon = parseFloat(locMatch[2]);
    const feat = _point(lon, lat, { tool: toolName, target, name: target });
    if (feat) return [feat];
  }

  const latMatch = text.match(/(?:Latitude|\[\+\]\s*Lat):\s*(-?[\d.]+)/i);
  const lonMatch = text.match(/(?:Longitude|\[\+\]\s*Lon):\s*(-?[\d.]+)/i);
  if (latMatch && lonMatch) {
    const lat = parseFloat(latMatch[1]);
    const lon = parseFloat(lonMatch[1]);
    const feat = _point(lon, lat, { tool: toolName, target, name: target });
    if (feat) return [feat];
  }

  return [];
}

/**
 * Whether a search_gdelt_geo result is the "service unavailable" answer (see
 * openosint/tools/search_gdelt_geo.py). Returns true / false for that tool and
 * null for any other tool, so callers leave the notice alone for unrelated results.
 */
export function gdeltServiceStatus(toolName, output) {
  if (toolName !== 'search_gdelt_geo') return null;
  return String(output || '').includes('[service_unavailable] search_gdelt_geo');
}

/**
 * How far back a search_gdelt_geo result reaches, from the `coverage` member of
 * its fenced FeatureCollection: {minutes, requested, loading, stale_minutes}.
 * Returns null for other tools and for results without a usable coverage (an
 * empty or failed search has no fence), and never throws. Values are coerced to
 * plain numbers/booleans so nothing third-party-controlled reaches the page.
 */
export function newsCoverage(toolName, output) {
  if (toolName !== 'search_gdelt_geo') return null;
  const m = _GEOJSON_FENCE_RE.exec(output || '');
  if (!m) return null;
  try {
    const c = JSON.parse(m[1]).coverage;
    const minutes = Number(c?.minutes);
    if (!c || !Number.isFinite(minutes) || minutes < 0) return null;
    return {
      minutes: Math.round(minutes),
      requested: Math.round(Number(c.requested)) || Math.round(minutes),
      loading: c.loading === true,
      staleMinutes: Math.max(0, Math.round(Number(c.stale_minutes)) || 0),
    };
  } catch {
    return null;
  }
}

/** "last 45 min" / "last 6 h" / "last 1 h 15 min" — plain text for the globe badge. */
export function coverageLabel(coverage) {
  if (!coverage) return '';
  const totalMin = Number.isFinite(coverage.minutes)
    ? coverage.minutes
    : (Number.isFinite(coverage.hours) ? coverage.hours * 60 : 0);
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  const span = h ? (m ? `${h} h ${m} min` : `${h} h`) : `${m} min`;
  const partial = Number.isFinite(coverage.requested) && totalMin < coverage.requested;
  let label = `News: last ${span}`;
  if (partial && coverage.loading) label += ' — older articles still loading';
  if (coverage.staleMinutes) label += ` — feed ${coverage.staleMinutes} min behind`;
  return label;
}

/** Most news places kept on the globe for one conversation; oldest dropped first. */
export const NEWS_FEATURE_CAP = 500;

function _placeKey(feature) {
  const [lon, lat] = feature.geometry.coordinates;
  return `${feature.properties?.name ?? ''}|${lon.toFixed(2)}|${lat.toFixed(2)}`;
}

/**
 * Merge a new search_gdelt_geo result into the places already on the globe.
 * One entry per place: a repeat replaces the older one and moves to the end,
 * so the cap drops the stalest places. Returns a new array; inputs are untouched.
 */
export function mergeNewsFeatures(existing, incoming, cap = NEWS_FEATURE_CAP) {
  const byPlace = new Map();
  for (const f of [...existing, ...incoming]) {
    if (!f?.geometry?.coordinates) continue;
    const key = _placeKey(f);
    byPlace.delete(key);
    byPlace.set(key, f);
  }
  return [...byPlace.values()].slice(-cap);
}
