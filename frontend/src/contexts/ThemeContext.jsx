// SPDX-License-Identifier: Apache-2.0
// Theme families: Pelagos' Mission Control (the default) and Pelagic, plus the UCM families.
// Each family writes its tokens as CSS variables on documentElement and its effects layer
// as data-effects; status colors keep their meaning, accent-primary is DNS, accent-pro DHCP.
import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { subscribePreferences, persistPreference, getPreferences } from '../stores/preferencesStore'

export const DEFAULT_FAMILY = 'mission'
const STORAGE_FAMILY = 'pelagos-theme-family'
const STORAGE_MODE = 'pelagos-theme-mode'
const MODES = ['system', 'dark', 'light']

export const themeFamilies = {
  mission: {
    id: 'mission',
    name: 'Mission Control',
    description: 'Graphite glass, ember and neon',
    accent: '#FF6A2B',
    effects: 'mission',
    dark: {
      'logo-gradient-start': '#FF7A3D',
      'logo-gradient-mid': '#FF5A1F',
      'logo-gradient-end': '#D9420E',
      'logo-gradient-accent': '#6CCFF6',
      'bg-primary': '#141B1D',
      'bg-secondary': '#1E2729',
      'bg-tertiary': '#283335',
      'text-primary': '#EEF3F2',
      'text-secondary': '#AEBBBA',
      'text-tertiary': '#93A3A2',
      'accent-primary': '#FF6A2B',
      'accent-success': '#3BE36B',
      'accent-warning': '#F5C518',
      'accent-warning-fill': '#F5C518',
      'accent-danger': '#FF5C76',
      'accent-pro': '#6CCFF6',
      'border': '#33403F',
      'gradient-from': '#FF6A2B',
      'gradient-to': '#FF8F4D',
      'gradient-button': 'linear-gradient(135deg, #FF7A3D, #F0581A)',
      'gradient-accent': 'linear-gradient(135deg, #FF6A2B 0%, #6CCFF6 100%)',
      'gradient-bg': 'linear-gradient(160deg, #1A2325 0%, #141B1D 55%, #101618 100%)',
      'detail-header-bg': 'linear-gradient(135deg, rgba(255,106,43,0.10), rgba(108,207,246,0.04), transparent)',
      'detail-header-border': 'rgba(255,255,255,0.07)',
      'detail-header-shadow': 'inset 0 1px 0 0 rgba(255,255,255,0.05)',
      'detail-icon-bg': 'linear-gradient(135deg, #FF7A3D, #E04F12)',
      'detail-icon-shadow': '0 0 18px rgba(255,106,43,0.35)',
      'detail-stats-border': 'rgba(255,255,255,0.07)',
      'detail-section-bg': 'rgba(38,48,51,0.55)',
      'detail-section-border': 'rgba(255,255,255,0.07)',
      'detail-field-bg': 'rgba(255,255,255,0.03)',
      'detail-field-border': 'rgba(255,255,255,0.06)',
      // Ember is DNS and actions, ice cyan is DHCP: icon tiles follow the same split
      'icon-orange-bg': 'rgba(255, 106, 43, 0.16)',
      'icon-orange-text': '#FF8A55',
      'icon-amber-bg': 'rgba(245, 197, 24, 0.14)',
      'icon-amber-text': '#F5C518',
      'icon-emerald-bg': 'rgba(59, 227, 107, 0.14)',
      'icon-emerald-text': '#3BE36B',
      'icon-blue-bg': 'rgba(255, 106, 43, 0.16)',
      'icon-blue-text': '#FF8A55',
      'icon-violet-bg': 'rgba(108, 207, 246, 0.14)',
      'icon-violet-text': '#6CCFF6',
      'icon-teal-bg': 'rgba(108, 207, 246, 0.14)',
      'icon-teal-text': '#6CCFF6',
    },
    light: {
      'logo-gradient-start': '#E0571C',
      'logo-gradient-mid': '#C2440F',
      'logo-gradient-end': '#9C3409',
      'logo-gradient-accent': '#0A6A8E',
      'bg-primary': '#E4EAEA',
      'bg-secondary': '#F8FAFA',
      'bg-tertiary': '#E9EFEF',
      'text-primary': '#10181A',
      'text-secondary': '#3D4B4E',
      'text-tertiary': '#4F5E61',
      'accent-primary': '#B23A0A',
      'accent-success': '#0C7331',
      'accent-warning': '#7F6200',
      // Bars and dots keep the yellow identity; only the text token is bound by AA.
      'accent-warning-fill': '#E0B000',
      'accent-danger': '#C01C42',
      'accent-pro': '#0A6A8E',
      'border': '#C9D3D3',
      'gradient-from': '#B23A0A',
      'gradient-to': '#E0571C',
      'gradient-button': 'linear-gradient(135deg, #C2440F, #A23408)',
      'gradient-accent': 'linear-gradient(135deg, #B23A0A 0%, #0A6A8E 100%)',
      'gradient-bg': 'linear-gradient(160deg, #EEF2F2 0%, #E4EAEA 55%, #DCE3E3 100%)',
      'detail-header-bg': 'linear-gradient(135deg, rgba(178,58,10,0.08), rgba(10,106,142,0.05), rgba(255,255,255,0.7))',
      'detail-header-border': 'rgba(16,24,26,0.08)',
      'detail-header-shadow': 'inset 0 1px 0 0 rgba(255,255,255,0.8)',
      'detail-icon-bg': 'linear-gradient(135deg, #D24E16, #A23408)',
      'detail-icon-shadow': '0 4px 14px rgba(178,58,10,0.28)',
      'detail-stats-border': 'rgba(16,24,26,0.08)',
      'detail-section-bg': 'rgba(255,255,255,0.55)',
      'detail-section-border': 'rgba(16,24,26,0.09)',
      'detail-field-bg': 'rgba(16,24,26,0.03)',
      'detail-field-border': 'rgba(16,24,26,0.07)',
      // Deeper icon colors for the light glass
      'icon-orange-bg': 'rgba(178, 58, 10, 0.10)',
      'icon-orange-text': '#B23A0A',
      'icon-amber-bg': 'rgba(127, 98, 0, 0.10)',
      'icon-amber-text': '#7F6200',
      'icon-emerald-bg': 'rgba(12, 115, 49, 0.10)',
      'icon-emerald-text': '#0C7331',
      'icon-blue-bg': 'rgba(178, 58, 10, 0.10)',
      'icon-blue-text': '#B23A0A',
      'icon-violet-bg': 'rgba(10, 106, 142, 0.10)',
      'icon-violet-text': '#0A6A8E',
      'icon-teal-bg': 'rgba(10, 106, 142, 0.10)',
      'icon-teal-text': '#0A6A8E',
    }
  },
  pelagic: {
    id: 'pelagic',
    name: 'Pelagic',
    description: 'Ocean Mission Control UI',
    accent: '#2DD4BF',
    effects: 'none',
    dark: {
      'logo-gradient-start': '#2DD4BF',
      'logo-gradient-mid': '#14B8A6',
      'logo-gradient-end': '#0F766E',
      'logo-gradient-accent': '#93C5FD',
      'bg-primary': '#061420',
      'bg-secondary': '#0B1E2E',
      'bg-tertiary': '#12293C',
      'text-primary': '#E6F3F5',
      'text-secondary': '#9FBFCB',
      'text-tertiary': '#8FADB9',
      'accent-primary': '#2DD4BF',
      'accent-success': '#34D399',
      'accent-warning': '#FBBF24',
      'accent-warning-fill': '#FBBF24',
      'accent-danger': '#F87171',
      'accent-pro': '#93C5FD',
      'border': '#1E3A4C',
      'gradient-from': '#2DD4BF',
      'gradient-to': '#93C5FD',
      'gradient-button': 'linear-gradient(135deg, #0F766E, #115E59)',
      'gradient-accent': 'linear-gradient(135deg, #2DD4BF 0%, #93C5FD 100%)',
      'gradient-bg': 'linear-gradient(145deg, #0B1E2E 0%, #0E2438 50%, #0B1E2E 100%)',
      'detail-header-bg': 'linear-gradient(135deg, rgba(45,212,191,0.08), rgba(147,197,253,0.04), transparent)',
      'detail-header-border': 'rgba(255,255,255,0.06)',
      'detail-header-shadow': 'inset 0 1px 0 0 rgba(255,255,255,0.04)',
      'detail-icon-bg': 'linear-gradient(135deg, #2DD4BF, rgba(45,212,191,0.7))',
      'detail-icon-shadow': '0 4px 12px rgba(45,212,191,0.25)',
      'detail-stats-border': 'rgba(255,255,255,0.06)',
      'detail-section-bg': 'rgba(11,30,46,0.6)',
      'detail-section-border': '#1E3A4C',
      'detail-field-bg': 'rgba(255,255,255,0.02)',
      'detail-field-border': 'rgba(255,255,255,0.05)',
      // Icon colors: turquoise is DNS and actions, violet stays for DHCP
      'icon-orange-bg': 'rgba(249, 115, 22, 0.15)',
      'icon-orange-text': '#FB923C',
      'icon-amber-bg': 'rgba(245, 158, 11, 0.15)',
      'icon-amber-text': '#FBBF24',
      'icon-emerald-bg': 'rgba(52, 211, 153, 0.15)',
      'icon-emerald-text': '#34D399',
      'icon-blue-bg': 'rgba(45, 212, 191, 0.15)',
      'icon-blue-text': '#2DD4BF',
      'icon-violet-bg': 'rgba(139, 92, 246, 0.15)',
      'icon-violet-text': '#A78BFA',
      'icon-teal-bg': 'rgba(147, 197, 253, 0.15)',
      'icon-teal-text': '#93C5FD',
    },
    light: {
      'logo-gradient-start': '#0F766E',
      'logo-gradient-mid': '#0D9488',
      'logo-gradient-end': '#115E59',
      'logo-gradient-accent': '#1D4ED8',
      'bg-primary': '#EEF5F7',
      'bg-secondary': '#FFFFFF',
      'bg-tertiary': '#DCE9EE',
      'text-primary': '#0B1E2E',
      'text-secondary': '#3C5B68',
      'text-tertiary': '#4A6977',
      'accent-primary': '#0F766E',
      'accent-success': '#059669',
      'accent-warning': '#D97706',
      'accent-warning-fill': '#D97706',
      'accent-danger': '#DC2626',
      'accent-pro': '#1D4ED8',
      'border': '#BFD3DB',
      'gradient-from': '#0F766E',
      'gradient-to': '#1D4ED8',
      'gradient-button': 'var(--gradient-primary)',
      'gradient-accent': 'linear-gradient(135deg, #0F766E 0%, #1D4ED8 100%)',
      'gradient-bg': 'linear-gradient(145deg, #EEF5F7 0%, #E3EFF3 50%, #EEF5F7 100%)',
      'detail-header-bg': 'linear-gradient(135deg, rgba(15,118,110,0.10), rgba(29,78,216,0.06), rgba(255,255,255,0.95))',
      'detail-header-border': 'rgba(15,118,110,0.12)',
      'detail-header-shadow': '0 1px 3px rgba(15,118,110,0.10)',
      'detail-icon-bg': 'linear-gradient(135deg, #0F766E, #0D9488)',
      'detail-icon-shadow': '0 4px 14px rgba(15,118,110,0.30)',
      'detail-stats-border': 'rgba(0,0,0,0.08)',
      'detail-section-bg': '#E8F1F4',
      'detail-section-border': '#BFD3DB',
      'detail-field-bg': 'rgba(0,0,0,0.035)',
      'detail-field-border': 'rgba(0,0,0,0.08)',
      // Icon colors: deeper for light mode
      'icon-orange-bg': 'rgba(234, 88, 12, 0.12)',
      'icon-orange-text': '#C2410C',
      'icon-amber-bg': 'rgba(217, 119, 6, 0.12)',
      'icon-amber-text': '#B45309',
      'icon-emerald-bg': 'rgba(5, 150, 105, 0.12)',
      'icon-emerald-text': '#047857',
      'icon-blue-bg': 'rgba(15, 118, 110, 0.12)',
      'icon-blue-text': '#0F766E',
      'icon-violet-bg': 'rgba(124, 58, 237, 0.12)',
      'icon-violet-text': '#6D28D9',
      'icon-teal-bg': 'rgba(29, 78, 216, 0.12)',
      'icon-teal-text': '#1D4ED8',
    }
  },
  gray: {
    id: 'gray',
    name: 'Gray',
    description: 'Neutral slate',
    accent: '#4F8EF7',
    effects: 'none',
    dark: {
      'logo-gradient-start': '#fb923c',
      'logo-gradient-mid': '#f97316',
      'logo-gradient-end': '#ea580c',
      'logo-gradient-accent': '#fbbf24',
      'bg-primary': '#12161C',
      'bg-secondary': '#1C222A',
      'bg-tertiary': '#252D38',
      'text-primary': '#F0F4F8',
      'text-secondary': '#A8B4C4',
      'text-tertiary': '#7E8A9A',
      'accent-primary': '#4F8EF7',
      'accent-success': '#34D399',
      'accent-warning': '#FBBF24',
      'accent-warning-fill': '#FBBF24',
      'accent-danger': '#F87171',
      'accent-pro': '#A78BFA',
      'border': '#3A4555',
      'gradient-from': '#4F8EF7',
      'gradient-to': '#A78BFA',
      'gradient-button': 'linear-gradient(135deg, #2563EB, #1D4ED8)',
      'gradient-accent': 'linear-gradient(135deg, #4F8EF7 0%, #A78BFA 100%)',
      'gradient-bg': 'linear-gradient(145deg, #1e2633 0%, #252035 50%, #1e2633 100%)',
      'detail-header-bg': 'linear-gradient(135deg, rgba(79,142,247,0.08), rgba(167,139,250,0.04), transparent)',
      'detail-header-border': 'rgba(255,255,255,0.06)',
      'detail-header-shadow': 'inset 0 1px 0 0 rgba(255,255,255,0.04)',
      'detail-icon-bg': 'linear-gradient(135deg, #4F8EF7, rgba(79,142,247,0.7))',
      'detail-icon-shadow': '0 4px 12px rgba(79,142,247,0.25)',
      'detail-stats-border': 'rgba(255,255,255,0.06)',
      'detail-section-bg': 'rgba(28,34,42,0.6)',
      'detail-section-border': '#3A4555',
      'detail-field-bg': 'rgba(255,255,255,0.02)',
      'detail-field-border': 'rgba(255,255,255,0.05)',
      // Icon colors - standard
      'icon-orange-bg': 'rgba(249, 115, 22, 0.15)',
      'icon-orange-text': '#FB923C',
      'icon-amber-bg': 'rgba(245, 158, 11, 0.15)',
      'icon-amber-text': '#FBBF24',
      'icon-emerald-bg': 'rgba(52, 211, 153, 0.15)',
      'icon-emerald-text': '#34D399',
      'icon-blue-bg': 'rgba(79, 142, 247, 0.15)',
      'icon-blue-text': '#60A5FA',
      'icon-violet-bg': 'rgba(139, 92, 246, 0.15)',
      'icon-violet-text': '#A78BFA',
      'icon-teal-bg': 'rgba(20, 184, 166, 0.15)',
      'icon-teal-text': '#2DD4BF',
    },
    light: {
      'logo-gradient-start': '#ea580c',
      'logo-gradient-mid': '#c2410c',
      'logo-gradient-end': '#9a3412',
      'logo-gradient-accent': '#d97706',
      'bg-primary': '#EFF2F7',
      'bg-secondary': '#FFFFFF',
      'bg-tertiary': '#E4E8EF',
      'text-primary': '#111827',
      'text-secondary': '#4B5563',
      'text-tertiary': '#6B7280',
      'accent-primary': '#2563EB',
      'accent-success': '#059669',
      'accent-warning': '#D97706',
      'accent-warning-fill': '#D97706',
      'accent-danger': '#DC2626',
      'accent-pro': '#7C3AED',
      'border': '#CBD5E1',
      'gradient-from': '#2563EB',
      'gradient-to': '#7C3AED',
      'gradient-button': 'var(--gradient-primary)',
      'gradient-accent': 'linear-gradient(135deg, #2563EB 0%, #7C3AED 100%)',
      'gradient-bg': 'linear-gradient(145deg, #EFF2F7 0%, #E8EDFB 50%, #EFF2F7 100%)',
      'detail-header-bg': 'linear-gradient(135deg, rgba(37,99,235,0.10), rgba(124,58,237,0.06), rgba(255,255,255,0.95))',
      'detail-header-border': 'rgba(37,99,235,0.12)',
      'detail-header-shadow': '0 1px 3px rgba(37,99,235,0.10)',
      'detail-icon-bg': 'linear-gradient(135deg, #2563EB, #4F46E5)',
      'detail-icon-shadow': '0 4px 14px rgba(37,99,235,0.30)',
      'detail-stats-border': 'rgba(0,0,0,0.08)',
      'detail-section-bg': '#F1F5F9',
      'detail-section-border': '#CBD5E1',
      'detail-field-bg': 'rgba(0,0,0,0.035)',
      'detail-field-border': 'rgba(0,0,0,0.08)',
      // Icon colors - stronger/deeper for light mode
      'icon-orange-bg': 'rgba(234, 88, 12, 0.12)',
      'icon-orange-text': '#C2410C',
      'icon-amber-bg': 'rgba(217, 119, 6, 0.12)',
      'icon-amber-text': '#B45309',
      'icon-emerald-bg': 'rgba(5, 150, 105, 0.12)',
      'icon-emerald-text': '#047857',
      'icon-blue-bg': 'rgba(37, 99, 235, 0.12)',
      'icon-blue-text': '#1D4ED8',
      'icon-violet-bg': 'rgba(124, 58, 237, 0.12)',
      'icon-violet-text': '#6D28D9',
      'icon-teal-bg': 'rgba(13, 148, 136, 0.12)',
      'icon-teal-text': '#0F766E',
    }
  },
  purple: {
    id: 'purple',
    name: 'Purple Night',
    description: 'Deep violet',
    accent: '#A855F7',
    effects: 'none',
    dark: {
      'logo-gradient-start': '#fb923c',
      'logo-gradient-mid': '#f97316',
      'logo-gradient-end': '#ea580c',
      'logo-gradient-accent': '#fbbf24',
      'bg-primary': '#1A0B2E',
      'bg-secondary': '#251438',
      'bg-tertiary': '#301E47',
      'text-primary': '#F3E8FF',
      'text-secondary': '#D4C5E9',
      'text-tertiary': '#AB9AC8',
      'accent-primary': '#A855F7',
      'accent-success': '#22C55E',
      'accent-warning': '#F59E0B',
      'accent-warning-fill': '#F59E0B',
      'accent-danger': '#F43F5E',
      'accent-pro': '#EC4899',
      'border': '#442B66',
      'gradient-from': '#A855F7',
      'gradient-to': '#EC4899',
      'gradient-button': 'linear-gradient(135deg, #7C3AED, #6D28D9)',
      'gradient-accent': 'linear-gradient(135deg, #A855F7 0%, #EC4899 100%)',
      'gradient-bg': 'linear-gradient(135deg, #3d2555 0%, #4a1942 100%)',
      'detail-header-bg': 'linear-gradient(135deg, rgba(168,85,247,0.08), rgba(236,72,153,0.04), transparent)',
      'detail-header-border': 'rgba(255,255,255,0.06)',
      'detail-header-shadow': 'inset 0 1px 0 0 rgba(255,255,255,0.04)',
      'detail-icon-bg': 'linear-gradient(135deg, #A855F7, rgba(168,85,247,0.7))',
      'detail-icon-shadow': '0 4px 12px rgba(168,85,247,0.25)',
      'detail-stats-border': 'rgba(255,255,255,0.06)',
      'detail-section-bg': 'rgba(37,20,56,0.6)',
      'detail-section-border': '#442B66',
      'detail-field-bg': 'rgba(255,255,255,0.02)',
      'detail-field-border': 'rgba(255,255,255,0.05)',
      // Icon colors - avoid violet/pink, use teal/cyan
      'icon-orange-bg': 'rgba(249, 115, 22, 0.35)',
      'icon-orange-text': '#FB923C',
      'icon-amber-bg': 'rgba(245, 158, 11, 0.35)',
      'icon-amber-text': '#FBBF24',
      'icon-emerald-bg': 'rgba(52, 211, 153, 0.15)',
      'icon-emerald-text': '#34D399',
      'icon-blue-bg': 'rgba(20, 184, 166, 0.15)',  // Teal instead
      'icon-blue-text': '#2DD4BF',
      'icon-violet-bg': 'rgba(20, 184, 166, 0.15)', // Teal instead
      'icon-violet-text': '#2DD4BF',
      'icon-teal-bg': 'rgba(52, 211, 153, 0.15)',  // Green
      'icon-teal-text': '#34D399',
    },
    light: {
      'logo-gradient-start': '#ea580c',
      'logo-gradient-mid': '#c2410c',
      'logo-gradient-end': '#9a3412',
      'logo-gradient-accent': '#d97706',
      'bg-primary': '#F0EBF8',
      'bg-secondary': '#FFFFFF',
      'bg-tertiary': '#E8DFF5',
      'text-primary': '#3B0764',
      'text-secondary': '#6B21A8',
      'text-tertiary': '#7C3AED',
      'accent-primary': '#A855F7',
      'accent-success': '#22C55E',
      'accent-warning': '#F59E0B',
      'accent-warning-fill': '#F59E0B',
      'accent-danger': '#F43F5E',
      'accent-pro': '#EC4899',
      'border': '#D8B4FE',
      'gradient-from': '#A855F7',
      'gradient-to': '#EC4899',
      'gradient-button': 'linear-gradient(135deg, #7C3AED, #6D28D9)',
      'gradient-accent': 'linear-gradient(135deg, #A855F7 0%, #EC4899 100%)',
      'gradient-bg': 'linear-gradient(145deg, #F0EBF8 0%, #EDE4FA 50%, #F0EBF8 100%)',
      'detail-header-bg': 'linear-gradient(135deg, rgba(168,85,247,0.12), rgba(236,72,153,0.06), rgba(255,255,255,0.95))',
      'detail-header-border': 'rgba(168,85,247,0.18)',
      'detail-header-shadow': '0 1px 3px rgba(168,85,247,0.12)',
      'detail-icon-bg': 'linear-gradient(135deg, #A855F7, #EC4899)',
      'detail-icon-shadow': '0 4px 14px rgba(168,85,247,0.30)',
      'detail-stats-border': 'rgba(168,85,247,0.12)',
      'detail-section-bg': 'rgba(243,232,255,0.6)',
      'detail-section-border': '#D8B4FE',
      'detail-field-bg': 'rgba(168,85,247,0.035)',
      'detail-field-border': 'rgba(168,85,247,0.12)',
      // Icon colors - avoid violet/pink
      'icon-orange-bg': 'rgba(234, 88, 12, 0.12)',
      'icon-orange-text': '#C2410C',
      'icon-amber-bg': 'rgba(217, 119, 6, 0.12)',
      'icon-amber-text': '#B45309',
      'icon-emerald-bg': 'rgba(5, 150, 105, 0.12)',
      'icon-emerald-text': '#047857',
      'icon-blue-bg': 'rgba(13, 148, 136, 0.12)',  // Teal
      'icon-blue-text': '#0F766E',
      'icon-violet-bg': 'rgba(13, 148, 136, 0.12)', // Teal
      'icon-violet-text': '#0F766E',
      'icon-teal-bg': 'rgba(5, 150, 105, 0.12)',
      'icon-teal-text': '#047857',
    }
  },
  sunset: {
    id: 'sunset',
    name: 'Orange Sunset',
    description: 'Warm amber',
    accent: '#F97316',
    effects: 'none',
    dark: {
      'logo-gradient-start': '#fb923c',
      'logo-gradient-mid': '#f97316',
      'logo-gradient-end': '#ea580c',
      'logo-gradient-accent': '#fbbf24',
      'bg-primary': '#1F0F0A',
      'bg-secondary': '#2A1510',
      'bg-tertiary': '#3A1F16',
      'text-primary': '#FFF4ED',
      'text-secondary': '#D9A688',
      'text-tertiary': '#B88A6B',
      'accent-primary': '#F97316',
      'accent-success': '#22C55E',
      'accent-warning': '#FBBF24',
      'accent-warning-fill': '#FBBF24',
      'accent-danger': '#DC2626',
      'accent-pro': '#A855F7',
      'border': '#4D2815',
      'gradient-from': '#F97316',
      'gradient-to': '#DC2626',
      'gradient-button': 'linear-gradient(135deg, #C2410C, #9A3412)',
      'gradient-accent': 'linear-gradient(135deg, #F97316 0%, #DC2626 100%)',
      'gradient-bg': 'linear-gradient(135deg, #4a2618 0%, #5c1a1a 100%)',
      'detail-header-bg': 'linear-gradient(135deg, rgba(249,115,22,0.08), rgba(220,38,38,0.04), transparent)',
      'detail-header-border': 'rgba(255,255,255,0.06)',
      'detail-header-shadow': 'inset 0 1px 0 0 rgba(255,255,255,0.04)',
      'detail-icon-bg': 'linear-gradient(135deg, #F97316, rgba(249,115,22,0.7))',
      'detail-icon-shadow': '0 4px 12px rgba(249,115,22,0.25)',
      'detail-stats-border': 'rgba(255,255,255,0.06)',
      'detail-section-bg': 'rgba(42,21,16,0.6)',
      'detail-section-border': '#4D2815',
      'detail-field-bg': 'rgba(255,255,255,0.02)',
      'detail-field-border': 'rgba(255,255,255,0.05)',
      // Icon colors - avoid orange/amber, use blue/teal
      'icon-orange-bg': 'rgba(59, 130, 246, 0.15)',  // Blue instead
      'icon-orange-text': '#60A5FA',
      'icon-amber-bg': 'rgba(20, 184, 166, 0.15)',  // Teal instead
      'icon-amber-text': '#2DD4BF',
      'icon-emerald-bg': 'rgba(52, 211, 153, 0.15)',
      'icon-emerald-text': '#34D399',
      'icon-blue-bg': 'rgba(59, 130, 246, 0.15)',
      'icon-blue-text': '#60A5FA',
      'icon-violet-bg': 'rgba(139, 92, 246, 0.15)',
      'icon-violet-text': '#A78BFA',
      'icon-teal-bg': 'rgba(20, 184, 166, 0.15)',
      'icon-teal-text': '#2DD4BF',
    },
    light: {
      'logo-gradient-start': '#ea580c',
      'logo-gradient-mid': '#c2410c',
      'logo-gradient-end': '#9a3412',
      'logo-gradient-accent': '#d97706',
      'bg-primary': '#F5EDE5',
      'bg-secondary': '#FFFFFF',
      'bg-tertiary': '#FDDCB5',
      'text-primary': '#611705',
      'text-secondary': '#9A3412',
      'text-tertiary': '#C2410C',
      'accent-primary': '#EA580C',
      'accent-success': '#22C55E',
      'accent-warning': '#FBBF24',
      'accent-warning-fill': '#FBBF24',
      'accent-danger': '#DC2626',
      'accent-pro': '#A855F7',
      'border': '#FDBA74',
      'gradient-from': '#F97316',
      'gradient-to': '#EA580C',
      'gradient-button': 'linear-gradient(135deg, #C2410C, #9A3412)',
      'gradient-accent': 'linear-gradient(135deg, #F97316 0%, #EA580C 100%)',
      'gradient-bg': 'linear-gradient(145deg, #F5EDE5 0%, #FDE8D0 50%, #F5EDE5 100%)',
      'detail-header-bg': 'linear-gradient(135deg, rgba(249,115,22,0.12), rgba(234,88,12,0.06), rgba(255,255,255,0.95))',
      'detail-header-border': 'rgba(249,115,22,0.18)',
      'detail-header-shadow': '0 1px 3px rgba(249,115,22,0.12)',
      'detail-icon-bg': 'linear-gradient(135deg, #F97316, #EA580C)',
      'detail-icon-shadow': '0 4px 14px rgba(249,115,22,0.30)',
      'detail-stats-border': 'rgba(249,115,22,0.12)',
      'detail-section-bg': 'rgba(255,237,213,0.6)',
      'detail-section-border': '#FDBA74',
      'detail-field-bg': 'rgba(249,115,22,0.035)',
      'detail-field-border': 'rgba(249,115,22,0.12)',
      // Icon colors - avoid orange/amber
      'icon-orange-bg': 'rgba(37, 99, 235, 0.12)',  // Blue
      'icon-orange-text': '#1D4ED8',
      'icon-amber-bg': 'rgba(13, 148, 136, 0.12)',  // Teal
      'icon-amber-text': '#0F766E',
      'icon-emerald-bg': 'rgba(5, 150, 105, 0.12)',
      'icon-emerald-text': '#047857',
      'icon-blue-bg': 'rgba(37, 99, 235, 0.12)',
      'icon-blue-text': '#1D4ED8',
      'icon-violet-bg': 'rgba(124, 58, 237, 0.12)',
      'icon-violet-text': '#6D28D9',
      'icon-teal-bg': 'rgba(13, 148, 136, 0.12)',
      'icon-teal-text': '#0F766E',
    }
  },
}

const ThemeContext = createContext()

function readSaved(key, valid) {
  try {
    const value = localStorage.getItem(key)
    return value && valid(value) ? value : null
  } catch {
    return null // localStorage unavailable (private browsing)
  }
}

export function ThemeProvider({ children }) {
  // Initial state comes from storage: no effect may write the defaults over a saved choice.
  const [themeFamily, setThemeFamily] = useState(
    () => readSaved(STORAGE_FAMILY, (v) => Boolean(themeFamilies[v])) ?? DEFAULT_FAMILY
  )
  const [mode, setMode] = useState(() => readSaved(STORAGE_MODE, (v) => MODES.includes(v)) ?? 'system')
  const [resolvedMode, setResolvedMode] = useState('dark')

  // Follow the OS preference while mode is "system".
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    const updateResolvedMode = () => {
      setResolvedMode(mode === 'system' ? (mediaQuery.matches ? 'dark' : 'light') : mode)
    }
    updateResolvedMode()
    mediaQuery.addEventListener('change', updateResolvedMode)
    return () => mediaQuery.removeEventListener('change', updateResolvedMode)
  }, [mode])

  // Apply the tokens and remember the choice.
  useEffect(() => {
    const family = themeFamilies[themeFamily]
    if (!family) return
    const root = document.documentElement
    Object.entries(family[resolvedMode]).forEach(([key, value]) => {
      root.style.setProperty(`--${key}`, value)
    })
    root.classList.toggle('theme-light', resolvedMode === 'light')
    root.dataset.theme = resolvedMode
    root.dataset.effects = family.effects || 'none'
    try {
      localStorage.setItem(STORAGE_FAMILY, themeFamily)
      localStorage.setItem(STORAGE_MODE, mode)
    } catch {
      // localStorage unavailable
    }
  }, [themeFamily, resolvedMode, mode])

  // Preferences coming back from the server (AuthContext) win over the local choice.
  useEffect(() => {
    const apply = (prefs) => {
      if (prefs.theme_family && themeFamilies[prefs.theme_family]) {
        setThemeFamily((prev) => (prev !== prefs.theme_family ? prefs.theme_family : prev))
      }
      if (prefs.theme_mode && MODES.includes(prefs.theme_mode)) {
        setMode((prev) => (prev !== prefs.theme_mode ? prefs.theme_mode : prev))
      }
    }
    apply(getPreferences())
    return subscribePreferences(apply)
  }, [])

  const setThemeFamilyAndPersist = useCallback((value) => {
    setThemeFamily(value)
    persistPreference('theme_family', value)
  }, [])
  const setModeAndPersist = useCallback((value) => {
    setMode(value)
    persistPreference('theme_mode', value)
  }, [])

  const currentTheme = `${themeFamily}-${resolvedMode}`
  const setCurrentTheme = useCallback((themeId) => {
    if (themeFamilies[themeId]) {
      setThemeFamilyAndPersist(themeId)
    } else if (themeId === 'dark' || themeId === 'light') {
      setModeAndPersist(themeId)
    }
  }, [setThemeFamilyAndPersist, setModeAndPersist])

  const themes = Object.values(themeFamilies)
  const isLight = resolvedMode === 'light'
  const effects = themeFamilies[themeFamily]?.effects || 'none'

  return (
    <ThemeContext.Provider value={{
      themeFamily,
      setThemeFamily: setThemeFamilyAndPersist,
      mode,
      setMode: setModeAndPersist,
      resolvedMode,
      isLight,
      effects,
      themes,
      themeFamilies,
      currentTheme,
      setCurrentTheme
    }}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error('useTheme must be used within ThemeProvider')
  }
  return context
}
