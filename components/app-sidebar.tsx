"use client"

import {
  ActivityIcon,
  BookOpenIcon,
  BugIcon,
  DatabaseIcon,
  FileChartColumnIcon,
  FingerprintIcon,
  GitBranchIcon,
  LayoutDashboardIcon,
  LockKeyholeIcon,
  SearchCheckIcon,
  Settings2Icon,
  ShieldCheckIcon,
} from "lucide-react"

import { NavDocuments } from "@/components/nav-documents"
import { NavMain } from "@/components/nav-main"
import { NavSecondary } from "@/components/nav-secondary"
import { NavUser } from "@/components/nav-user"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"

const data = {
  user: {
    name: "Local operator",
    email: "evidence first",
    avatar: "",
  },
  navMain: [
    {
      title: "Dashboard",
      url: "#",
      icon: <LayoutDashboardIcon />,
    },
    {
      title: "Audit run",
      url: "#",
      icon: <ActivityIcon />,
    },
    {
      title: "Findings",
      url: "#",
      icon: <SearchCheckIcon />,
    },
    {
      title: "Canaries",
      url: "#",
      icon: <FingerprintIcon />,
    },
    {
      title: "Rules",
      url: "#",
      icon: <ShieldCheckIcon />,
    },
  ],
  evidence: [
    {
      name: "Reports",
      url: "#",
      icon: <FileChartColumnIcon />,
    },
    {
      name: "Fixtures",
      url: "#",
      icon: <DatabaseIcon />,
    },
    {
      name: "Methodology",
      url: "#",
      icon: <BookOpenIcon />,
    },
  ],
  navSecondary: [
    {
      title: "Safe testing",
      url: "#",
      icon: <LockKeyholeIcon />,
    },
    {
      title: "Integrations",
      url: "#",
      icon: <GitBranchIcon />,
    },
    {
      title: "Settings",
      url: "#",
      icon: <Settings2Icon />,
    },
  ],
}

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  return (
    <Sidebar collapsible="offcanvas" {...props}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              asChild
              className="data-[slot=sidebar-menu-button]:p-1.5!"
            >
              <a href="#">
                <BugIcon />
                <span className="text-base font-semibold">RelayProbe</span>
              </a>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={data.navMain} />
        <NavDocuments items={data.evidence} />
        <NavSecondary items={data.navSecondary} className="mt-auto" />
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={data.user} />
      </SidebarFooter>
    </Sidebar>
  )
}

