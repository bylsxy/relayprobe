import type { CSSProperties } from "react"

import { AppSidebar } from "@/components/app-sidebar"
import { RelayProbeConsole } from "@/components/relayprobe-console"
import { SiteHeader } from "@/components/site-header"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"

export default function Page() {
  return (
    <SidebarProvider
      style={
        {
          "--sidebar-width": "calc(var(--spacing) * 68)",
          "--header-height": "calc(var(--spacing) * 12)",
        } as CSSProperties
      }
    >
      <AppSidebar variant="inset" />
      <SidebarInset>
        <SiteHeader />
        <RelayProbeConsole />
      </SidebarInset>
    </SidebarProvider>
  )
}

