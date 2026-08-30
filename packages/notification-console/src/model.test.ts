import { describe, expect, it } from "vitest";
import {
  createNotificationBusinessApi,
  notificationBusinessApiContract,
} from "./business-api";
import { notificationConsoleManifest } from "./manifest";

describe("Notification Console contract", () => {
  it("owns exactly the Deliveries route", () => {
    expect(notificationConsoleManifest.surfaces).toHaveLength(1);
    expect(notificationConsoleManifest.surfaces[0]?.path).toBe("/notifications/deliveries");
  });

  it("keeps ciphertext and rendered bodies out of Business API schemas", () => {
    const contract = JSON.stringify(notificationBusinessApiContract);
    expect(contract).not.toContain("ciphertext");
    expect(contract).not.toContain("invitation_url");
    expect(contract).not.toContain('"html"');
    expect(contract).not.toContain('"subject"');
  });

  it("separates read and retry capabilities", () => {
    const paths = notificationBusinessApiContract.paths;
    expect(paths["/deliveries"].get["x-lenso-capability"]).toBe("notification.deliveries.read");
    expect(paths["/deliveries/{id}/retry"].post["x-lenso-capability"]).toBe("notification.deliveries.retry");
  });

  it("binds retry idempotency to both the Surface context and business input", async () => {
    let request: Record<string, unknown> | undefined;
    const api = createNotificationBusinessApi({
      identity: {
        moduleId: "lenso.notification",
        moduleReleaseDigest: `sha256:${"1".repeat(64)}`,
        uiArtifactDigest: `sha256:${"2".repeat(64)}`,
      },
      managedServiceContext: {},
      surfaceApi: {
        invoke: async (value: Record<string, unknown>) => {
          request = value;
          return { output: {} };
        },
      },
    } as never);

    await api.retryDelivery("ntf_delivery_1", 4, "retry-key-1");

    expect(request?.requestContext).toMatchObject({
      idempotencyKey: "retry-key-1",
    });
    expect(request?.input).toEqual({
      id: "ntf_delivery_1",
      idempotency_key: "retry-key-1",
      revision: 4,
    });
  });
});
