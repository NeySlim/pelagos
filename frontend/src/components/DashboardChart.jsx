// SPDX-License-Identifier: Apache-2.0
// Recharts wrappers that read their colors from the theme tokens, so every chart
// follows the active family and mode. Color names: primary (DNS), pro (DHCP),
// success, warning, danger.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts'
import { useTheme } from '../contexts/ThemeContext'
import { MiniHistogram } from './motion/Charts'

const FALLBACK = { primary: '#2DD4BF', pro: '#93C5FD', success: '#34D399', warning: '#FBBF24', danger: '#F87171', grid: '#1E3A4C', text: '#9FBFCB' }

function cssVar(name) {
  if (typeof document === 'undefined') return ''
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

export function useChartColors() {
  const { themeFamily, resolvedMode } = useTheme()
  const [colors, setColors] = useState(FALLBACK)
  useEffect(() => {
    // ThemeContext writes the variables in an effect; read them on the next tick.
    const timer = setTimeout(() => {
      setColors({
        primary: cssVar('--accent-primary') || FALLBACK.primary,
        pro: cssVar('--accent-pro') || FALLBACK.pro,
        success: cssVar('--accent-success') || FALLBACK.success,
        warning: cssVar('--accent-warning') || FALLBACK.warning,
        danger: cssVar('--accent-danger') || FALLBACK.danger,
        grid: cssVar('--border') || FALLBACK.grid,
        text: cssVar('--text-tertiary') || FALLBACK.text,
      })
    }, 30)
    return () => clearTimeout(timer)
  }, [themeFamily, resolvedMode])
  return colors
}

function ChartTooltip({ active, payload, label, labelFormatter }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-bg-secondary border border-border rounded-lg px-3 py-2 shadow-lg">
      <p className="text-xs text-text-secondary mb-1">{labelFormatter ? labelFormatter(label) : label}</p>
      {payload.map((entry, i) => (
        <p key={entry.name || i} className="text-sm font-medium" style={{ color: entry.color }}>
          {entry.name}: {entry.value}
        </p>
      ))}
    </div>
  )
}

function NoData() {
  const { t } = useTranslation()
  return <div className="flex items-center justify-center h-full text-text-tertiary text-sm">{t('common.noDataAvailable')}</div>
}

// series: [{ key, label, color }]; data: [{ [xKey]: ..., [key]: number }]
export function TrendAreaChart({ data = [], series = [], xKey = 'ts', height = '100%', xFormatter, stacked = false }) {
  const colors = useChartColors()
  // The Mission family fills areas with a dot stipple instead of a gradient wash.
  const stipple = useTheme().effects === 'mission'
  if (!data.length || !series.length) return <NoData />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <defs>
          {series.map((s) =>
            stipple ? (
              <pattern key={s.key} id={`trend-${s.key}`} width="6" height="6" patternUnits="userSpaceOnUse">
                <circle cx="3" cy="3" r="1" fill={colors[s.color] || s.color || colors.primary} fillOpacity={0.6} />
              </pattern>
            ) : (
              <linearGradient key={s.key} id={`trend-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={colors[s.color] || s.color || colors.primary} stopOpacity={0.3} />
                <stop offset="95%" stopColor={colors[s.color] || s.color || colors.primary} stopOpacity={0} />
              </linearGradient>
            ),
          )}
        </defs>
        <XAxis dataKey={xKey} tick={{ fontSize: 10, fill: colors.text }} tickFormatter={xFormatter} axisLine={false} tickLine={false} />
        <YAxis tick={{ fontSize: 10, fill: colors.text }} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip content={<ChartTooltip labelFormatter={xFormatter} />} />
        {series.map((s) => (
          <Area
            key={s.key}
            type="monotone"
            dataKey={s.key}
            name={s.label || s.key}
            stackId={stacked ? 'stack' : undefined}
            stroke={colors[s.color] || s.color || colors.primary}
            fill={`url(#trend-${s.key})`}
            strokeWidth={stipple ? 1.25 : 2}
            activeDot={stipple ? { r: 4, strokeWidth: 0, style: { filter: 'drop-shadow(0 0 4px currentColor)' } } : undefined}
            isAnimationActive={false}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  )
}

// segments: [{ key, name, value, color }]; color is a token name or a CSS color.
export function DistributionPieChart({ segments = [], height = '100%', onSegmentClick }) {
  const colors = useChartColors()
  const data = useMemo(() => segments.filter((s) => s.value > 0), [segments])
  if (!data.length) return <NoData />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          innerRadius="55%"
          outerRadius="80%"
          paddingAngle={2}
          isAnimationActive={false}
          onClick={onSegmentClick ? (entry) => onSegmentClick(entry.key) : undefined}
        >
          {data.map((s) => (
            <Cell key={s.key || s.name} fill={colors[s.color] || s.color || colors.primary} stroke="none" />
          ))}
        </Pie>
        <Tooltip content={<ChartTooltip />} />
        <Legend
          verticalAlign="middle"
          align="right"
          layout="vertical"
          iconSize={8}
          iconType="circle"
          wrapperStyle={{ fontSize: 11, paddingLeft: 4 }}
          formatter={(value) => <span className="text-text-secondary">{value}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}

export function MiniSparkline({ data = [], color = 'primary', height = 30 }) {
  const colors = useChartColors()
  const { effects } = useTheme()
  const stroke = colors[color] || colors.primary
  if (data.length === 0) return null
  if (effects === 'mission') return <MiniHistogram data={data} tone={color} height={height} />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id={`spark-${color}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={stroke} stopOpacity={0.3} />
            <stop offset="95%" stopColor={stroke} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area type="basis" dataKey="value" stroke={stroke} fill={`url(#spark-${color})`} strokeWidth={1.5} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  )
}
