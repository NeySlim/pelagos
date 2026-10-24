// SPDX-License-Identifier: Apache-2.0
// Shared components. Pages import from here; area-specific components stay in their area.

// Layout
export { AppShell } from './AppShell'
export { Sidebar } from './Sidebar'
export { PageLayout } from './PageLayout'
export { Logo } from './Logo'
export { ErrorBoundary } from './ErrorBoundary'
export { WebSocketIndicator } from './WebSocketIndicator'

// Primitives (UCM design system)
export { Card } from './Card'
export { Button } from './Button'
export { Badge } from './Badge'
export { IconBadge, IconAvatar } from './IconBadge'
export { Input } from './Input'
export { Textarea } from './Textarea'
export { SelectComponent } from './Select'
export { Select, FilterSelect, FormSelect } from './ui/Select'
export { MultiSelectFilter } from './ui/MultiSelectFilter'
export { default as TagsInput } from './ui/TagsInput'
export { default as ToggleSwitch } from './ui/ToggleSwitch'
export { Dropdown } from './Dropdown'
export { TabsComponent as Tabs } from './Tabs'
export { TooltipComponent as Tooltip, HelpTooltip } from './Tooltip'
export { StatusIndicator } from './StatusIndicator'
export { LoadingSpinner } from './LoadingSpinner'
export { EmptyState } from './EmptyState'
export { Pagination } from './Pagination'
export { SearchBar } from './SearchBar'
export { TreeView } from './TreeView'
export { Modal } from './Modal'
export { Form } from './Form'
export { FormModal, ConfirmModal } from './FormModal'
export { FilterChips } from './ui/FilterChips'
export { RichStatsBar } from './ui/RichStatsBar'
export { UnifiedPageHeader } from './ui/UnifiedPageHeader'
export { MobileCard, SimpleMobileCard } from './ui/MobileCard'
export { FloatingWindow } from './ui/FloatingWindow'
export {
  DetailHeader, DetailSection, DetailGrid, DetailField, DetailDivider, DetailContent, DetailTabs,
  CompactSection, CompactGrid, CompactField, CompactStats, CompactActions, CompactHeader,
} from './DetailCard'

// Pelagos components
export { DataTable } from './DataTable'
export { ConfirmDialog } from './ConfirmDialog'
export { StatusBadge, statusVariant } from './StatusBadge'
export { UtilizationBar, utilizationLevel } from './UtilizationBar'
export { JsonTree } from './JsonTree'
export { DiffView, parseUnifiedDiff } from './DiffView'
export { PlanPreview, PlanPreviewModal } from './PlanPreview'
export { FloatingDetailWindow, DetailWindowLayer, registerDetailRenderer, getDetailRenderer, useOpenDetail } from './FloatingDetailWindow'
// Charts are loaded by the pages that need them: import from './DashboardChart'

// Motion and Mission effects primitives
export {
  CountUp, useCountUp, StatusDot, PulsingHalo, FlowLine, Reticle, RadarRing,
  MiniHistogram, StippledAreaChart, SegmentedProgress, Stagger, PageTransition, StatChip, IconButton, AppBackdrop,
} from './motion'
