import { CONSOLE_MODULE_API_PROTOCOL, defineConsoleManifest } from "@lenso/console-module-api";

export const notificationConsoleManifest = defineConsoleManifest({
  consoleUi: "^2.0.0",
  hostApi: "^2.1.0",
  moduleId: "lenso/notification",
  protocol: CONSOLE_MODULE_API_PROTOCOL,
  surfaces: [
    {
      area: "runtime",
      icon: "activity",
      id: "deliveries",
      label: "Deliveries",
      navigation: {
        group: { icon: "activity", id: "transactional", label: "Transactional", order: 10 },
        order: 10,
        workspace: { icon: "workflow", id: "notifications", label: "Notifications" }
      },
      path: "/notifications/deliveries",
      requiredCapabilities: ["notification.deliveries.read"]
    }
  ]
});
