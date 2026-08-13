import { defineConsoleUiModule } from "@lenso/console-ui";
import "@lenso/console-ui/stylex.css";
import { NotificationDeliveriesPage } from "./page";
import { notificationConsoleManifest } from "./manifest";

export const notificationConsoleUiModule = defineConsoleUiModule({
  manifest: notificationConsoleManifest,
  surfaces: { deliveries: NotificationDeliveriesPage }
});

export { NotificationDeliveriesPage };
export default notificationConsoleUiModule;
