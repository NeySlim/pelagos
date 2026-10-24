// SPDX-License-Identifier: Apache-2.0
// Providers and the router. Routes come from the area registry (pages/routes.js);
// each one is gated by the session, its permission and its module flag.
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { Suspense } from 'react'
import { AuthProvider, ThemeProvider, NotificationProvider, MobileProvider, WindowManagerProvider, useAuth } from './contexts'
import { WebSocketProvider } from './hooks/useWebSocket'
import { AppShell } from './components/AppShell'
import { ErrorBoundary } from './components/ErrorBoundary'
import { LoadingSpinner } from './components/LoadingSpinner'
import { DetailWindowLayer } from './components/FloatingDetailWindow'
import { RouteStatus } from './components/RouteStatus'
import LoginPage from './pages/auth/LoginPage'
import { allRoutes } from './pages/routes'
import { permitted } from './lib/access'

export function PageLoader() {
  return (
    <div className="flex items-center justify-center h-full min-h-[300px]" data-testid="page-loader">
      <LoadingSpinner size="lg" />
    </div>
  )
}

export function Protected({ permission, anyPermission, module, children }) {
  const { isAuthenticated, loading, hasPermission, modules, capabilities } = useAuth()
  const location = useLocation()
  if (loading) return <PageLoader />
  if (!isAuthenticated) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  if (!permitted({ permission, anyPermission }, hasPermission)) return <RouteStatus kind="forbidden" />
  if (module && !capabilities) return <PageLoader />
  if (module && !modules?.[module]) return <RouteStatus kind="module_disabled" />
  return children
}

export function AppRoutes() {
  const { isAuthenticated, loading } = useAuth()
  return (
    <Suspense fallback={<PageLoader />}>
      <Routes>
        <Route path="/login" element={loading ? <PageLoader /> : isAuthenticated ? <Navigate to="/" replace /> : <LoginPage />} />
        <Route element={<AppShell />}>
          {allRoutes.map(({ path, component: Page, props, permission, anyPermission, module }) => (
            <Route
              key={path}
              path={path}
              element={
                <Protected permission={permission} anyPermission={anyPermission} module={module}>
                  <Suspense fallback={<PageLoader />}>
                    <Page {...props} />
                  </Suspense>
                </Protected>
              }
            />
          ))}
          <Route path="*" element={<Protected><RouteStatus kind="not_found" /></Protected>} />
        </Route>
      </Routes>
    </Suspense>
  )
}

export default function App({ wsClient }) {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <BrowserRouter>
          <AuthProvider>
            <NotificationProvider>
              <WebSocketProvider client={wsClient}>
                <MobileProvider>
                  <WindowManagerProvider>
                    <AppRoutes />
                    <DetailWindowLayer />
                  </WindowManagerProvider>
                </MobileProvider>
              </WebSocketProvider>
            </NotificationProvider>
          </AuthProvider>
        </BrowserRouter>
      </ThemeProvider>
    </ErrorBoundary>
  )
}
