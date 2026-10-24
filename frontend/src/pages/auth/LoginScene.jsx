// SPDX-License-Identifier: Apache-2.0
// Atmospheric scene behind the sign-in form (Mission family): a wide radar disc on the
// ground with its sweep, waypoint halos and beams rising from two of them. Decorative
// only; every loop is an fx-loop transform, stopped by the motion level.
import { FlowLine, PulsingHalo, RadarRing } from '../../components/motion'
import './login.css'

// Waypoints in percent of the disc box; `beam` ones carry a rising dashed beam.
const WAYPOINTS = [
  { left: 24, top: 58, tone: 'success', beam: true },
  { left: 76, top: 52, tone: 'primary', beam: true },
  { left: 60, top: 72, tone: 'neutral' },
  { left: 40, top: 33, tone: 'neutral' },
]

export function LoginScene() {
  return (
    <div className="login-scene" aria-hidden="true" data-testid="login-scene">
      <div className="login-scene-disc">
        <RadarRing size={1200} tilt={70} tone="primary" />
        {WAYPOINTS.map((w, i) => (
          <span key={i} className="login-scene-point" style={{ left: `${w.left}%`, top: `${w.top}%` }}>
            {w.beam && <FlowLine direction="vertical" tone={w.tone} length="120px" thickness={1} reverse className="login-scene-beam" />}
            <PulsingHalo tone={w.tone} size={70} rings={2} />
          </span>
        ))}
      </div>
    </div>
  )
}

export default LoginScene
