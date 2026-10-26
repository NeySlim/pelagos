// SPDX-License-Identifier: Apache-2.0
// Step logic of the install and import wizard, kept pure so it is unit tested.
// Install puts engines that are missing on this node (distro or ISC packages);
// import adopts engines that are already installed (include line, sockets, keys).
// The last step builds the plan (POST /install/plan or /install/import/plan).

export const ENGINES = ['bind', 'kea4', 'kea6', 'd2']
export const SOURCES = ['distro', 'isc']
export const ISC_SERIES = ['2.6', '3.0', '3.2']
export const DEFAULT_ISC_SERIES = '3.2'
const KEA = new Set(['kea4', 'kea6', 'd2'])

export function stepsFor(mode) {
  return mode === 'install' ? ['mode', 'engines', 'source', 'review'] : ['mode', 'engines', 'review']
}

const installed = (detect, engine) => Boolean(detect?.engines?.[engine]?.installed)
// Installed but neither running nor enabled (e.g. only the package default config exists).
const inactive = (detect, engine) => {
  const e = detect?.engines?.[engine]
  return Boolean(e?.installed) && e.running === false && e.enabled === false
}

// What the node needs: nothing installed means install, anything installed means import.
export function suggestMode(detect) {
  return ENGINES.some((e) => installed(detect, e)) ? 'import' : 'install'
}

// Every engine with whether it can be chosen in this mode and why not.
export function engineChoices(mode, detect, modules = {}) {
  return ENGINES.map((engine) => {
    let reason = null
    if (engine === 'kea6' && modules.dhcpv6 === false) reason = 'module'
    else if (mode === 'install' && installed(detect, engine)) reason = 'installed'
    else if (mode === 'import' && !installed(detect, engine)) reason = 'notInstalled'
    const note = reason === null && mode === 'import' && inactive(detect, engine) ? 'inactive' : null
    return { engine, selectable: reason === null, reason, note }
  })
}

export function defaultEngines(mode, detect, modules = {}) {
  // Import keeps only the daemons that run or are enabled; the others stay selectable but unchecked.
  const selectable = engineChoices(mode, detect, modules).filter((c) => c.selectable && !c.note).map((c) => c.engine)
  // A fresh install proposes DNS, DHCPv4 and DDNS; DHCPv6 stays opt-in.
  return mode === 'install' ? selectable.filter((e) => e !== 'kea6') : selectable
}

export function initialState(detect, modules = {}) {
  const mode = suggestMode(detect)
  return { mode, step: 'mode', engines: defaultEngines(mode, detect, modules), source: 'distro', iscSeries: DEFAULT_ISC_SERIES }
}

export function setMode(state, mode, detect, modules = {}) {
  return { ...state, mode, engines: defaultEngines(mode, detect, modules) }
}

export function toggleEngine(state, engine) {
  const has = state.engines.includes(engine)
  const engines = has ? state.engines.filter((e) => e !== engine) : [...state.engines, engine]
  return { ...state, engines: ENGINES.filter((e) => engines.includes(e)) }
}

// Error code for the current step, or null when the wizard may go on.
export function validateStep(state, detect, modules = {}) {
  switch (state.step) {
    case 'mode':
      return ['install', 'import'].includes(state.mode) ? null : 'mode'
    case 'engines': {
      if (!state.engines.length) return 'noEngine'
      const choices = engineChoices(state.mode, detect, modules)
      if (state.engines.some((e) => !choices.find((c) => c.engine === e)?.selectable)) return 'notSelectable'
      if (state.engines.includes('d2')) {
        const keaPresent = ['kea4', 'kea6'].some((e) => state.engines.includes(e) || installed(detect, e))
        if (!keaPresent) return 'd2NeedsKea'
      }
      return null
    }
    case 'source':
      if (!SOURCES.includes(state.source)) return 'source'
      if (state.source === 'isc' && !ISC_SERIES.includes(state.iscSeries)) return 'series'
      return null
    default:
      return null
  }
}

export function canGoNext(state, detect, modules) {
  const steps = stepsFor(state.mode)
  return steps.indexOf(state.step) < steps.length - 1 && validateStep(state, detect, modules) === null
}

export function next(state, detect, modules) {
  if (!canGoNext(state, detect, modules)) return state
  const steps = stepsFor(state.mode)
  return { ...state, step: steps[steps.indexOf(state.step) + 1] }
}

export function prev(state) {
  const steps = stepsFor(state.mode)
  const index = steps.indexOf(state.step)
  return index > 0 ? { ...state, step: steps[index - 1] } : state
}

// Whether the ISC series matters: only Kea comes from the ISC repositories by series.
export const needsSeries = (state) => state.source === 'isc' && state.engines.some((e) => KEA.has(e))

// Request body and API call for the review step.
export function buildRequest(state) {
  if (state.mode === 'import') return { kind: 'import', body: { engines: state.engines } }
  const body = { engines: state.engines, source: state.source }
  if (needsSeries(state)) body.isc_series = state.iscSeries
  return { kind: 'install', body }
}
