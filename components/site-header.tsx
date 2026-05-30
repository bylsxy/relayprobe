import { CodeIcon, ShieldCheckIcon } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { SidebarTrigger } from "@/components/ui/sidebar"

export function SiteHeader() {
  return (
    <header className="flex h-(--header-height) shrink-0 items-center gap-2 border-b transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-(--header-height)">
      <div className="flex w-full items-center justify-between gap-3 px-4 lg:px-6">
        <div className="flex min-w-0 items-center gap-1 lg:gap-2">
          <SidebarTrigger className="-ml-1" />
          <Separator
            orientation="vertical"
            className="mx-2 data-[orientation=vertical]:h-4"
          />
          <div className="flex min-w-0 items-center gap-2">
            <h1 className="truncate text-base font-medium">Relay audit</h1>
            <Badge variant="secondary" className="hidden sm:inline-flex">
              Evidence-based
            </Badge>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Badge variant="outline" className="hidden md:inline-flex">
            <ShieldCheckIcon />
            Safe canaries
          </Badge>
          <Button variant="outline" size="sm" asChild>
            <a
              href="https://github.com/"
              target="_blank"
              rel="noreferrer noopener"
            >
              <CodeIcon data-icon="inline-start" />
              Source
            </a>
          </Button>
        </div>
      </div>
    </header>
  )
}
