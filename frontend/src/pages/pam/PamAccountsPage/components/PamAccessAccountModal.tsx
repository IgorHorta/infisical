import { useEffect, useMemo, useState } from "react";
import { faCopy } from "@fortawesome/free-regular-svg-icons";
import { faGlobe, faUpRightFromSquare } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import ms from "ms";

import { createNotification } from "@app/components/notifications";
import { Button, FormLabel, IconButton, Input, Modal, ModalContent, Select, SelectItem } from "@app/components/v2";
import { PamResourceType, TPamAccount, useAccessPamAccount } from "@app/hooks/api/pam";

import { PostgreSQLTerminal } from "../../SqlBrowserPage/components/PostgreSQLTerminal";

type AccessType = "cli" | "browser";

type Props = {
  account?: TPamAccount;
  accountPath?: string;
  isOpen: boolean;
  onOpenChange: (isOpen: boolean) => void;
  projectId: string;
};

export const PamAccessAccountModal = ({
  isOpen,
  onOpenChange,
  account,
  projectId,
  accountPath
}: Props) => {
  const [duration, setDuration] = useState("4h");
  const [accessType, setAccessType] = useState<AccessType>("cli");
  const [terminalSessionId, setTerminalSessionId] = useState<string | null>(null);

  const { mutateAsync: accessAccount, isPending: isAccessing } = useAccessPamAccount();

  const { protocol, hostname, port } = window.location;
  const portSuffix = port && port !== "80" && port !== "443" ? `:${port}` : "";
  const siteURL = `${protocol}//${hostname}${portSuffix}`;

  let fullAccountPath = account?.name ?? "";
  if (accountPath) {
    const path = accountPath.replace(/^\/+|\/+$/g, "");
    fullAccountPath = `${path}/${account?.name ?? ""}`;
  }

  const isDurationValid = useMemo(() => duration && ms(duration || "1s") > 0, [duration]);

  // Check if browser access is supported for this resource type
  const supportsBrowserAccess = account?.resource.resourceType === PamResourceType.Postgres;

  // Reset access type and terminal when modal opens or account changes
  useEffect(() => {
    if (isOpen && account) {
      setAccessType(supportsBrowserAccess ? "browser" : "cli");
      setTerminalSessionId(null);
    }
  }, [isOpen, account, supportsBrowserAccess]);

  const handleCliAccess = () => {
    if (!account) return;

    navigator.clipboard.writeText(command);
    createNotification({
      text: "Command copied to clipboard",
      type: "info"
    });
    onOpenChange(false);
  };

  const handleBrowserAccess = async () => {
    if (!account || !isDurationValid) return;

    try {
      const response = await accessAccount({
        accountId: account.id,
        accountPath: fullAccountPath,
        projectId,
        duration: cliDuration
      });

      // Show terminal in modal
      setTerminalSessionId(response.sessionId);
    } catch (error) {
      createNotification({
        text: "Failed to access account",
        type: "error"
      });
    }
  };

  const cliDuration = useMemo(() => {
    if (!duration) return duration;

    const unit = duration.replace(/[\d\s.-]/g, "");

    const dayOrLargerUnits = [
      "d",
      "day",
      "days",
      "w",
      "week",
      "weeks",
      "y",
      "yr",
      "yrs",
      "year",
      "years"
    ];

    // ms library does not handle months (M) so we do it separately
    if (unit === "M") {
      const value = parseInt(duration, 10);
      if (!Number.isNaN(value) && value > 0) {
        const hours = value * 30 * 24;
        return `${hours}h`;
      }
    } else if (dayOrLargerUnits.includes(unit.toLowerCase())) {
      const valueInMs = ms(duration);
      const oneHourInMs = 1000 * 60 * 60;

      if (typeof valueInMs === "number" && valueInMs > 0) {
        const hours = Math.floor(valueInMs / oneHourInMs);
        return `${hours}h`;
      }
    }

    return duration;
  }, [duration]);

  const command = useMemo(() => {
    if (!account) return "";

    switch (account.resource.resourceType) {
      case PamResourceType.Postgres:
      case PamResourceType.MySQL:
        return `infisical pam db access-account ${fullAccountPath} --project-id ${projectId} --duration ${cliDuration} --domain ${siteURL}`;
      case PamResourceType.Redis:
        return `infisical pam redis access-account ${fullAccountPath} --project-id ${projectId} --duration ${cliDuration} --domain ${siteURL}`;
      case PamResourceType.SSH:
        return `infisical pam ssh access-account ${fullAccountPath} --project-id ${projectId} --duration ${cliDuration} --domain ${siteURL}`;
      case PamResourceType.Kubernetes:
        return `infisical pam kubernetes access-account ${fullAccountPath} --project-id ${projectId} --duration ${cliDuration} --domain ${siteURL}`;
      default:
        return "";
    }
  }, [account, fullAccountPath, projectId, cliDuration, siteURL]);

  if (!account) return null;

  return (
    <Modal isOpen={isOpen} onOpenChange={onOpenChange}>
      <ModalContent
        className={terminalSessionId ? "max-w-4xl" : "max-w-2xl pb-2"}
        title={terminalSessionId ? "PostgreSQL Terminal" : "Access Account"}
        subTitle={terminalSessionId ? "Interactive PostgreSQL command-line interface" : `Access ${account.name} using a CLI command.`}
      >
        {terminalSessionId ? (
          <PostgreSQLTerminal
            accountId={account.id}
            sessionId={terminalSessionId}
          />
        ) : (
          <>
            <FormLabel
              label="Duration"
              tooltipText="The maximum duration of your session. Ex: 1h, 3w, 30d"
            />
            <Input
              value={duration}
              onChange={(e) => setDuration(e.target.value)}
              placeholder="permanent"
              isError={!isDurationValid}
            />

            {supportsBrowserAccess && (
              <>
                <FormLabel label="Access Type" className="mt-4" />
                <Select
                  value={accessType}
                  onValueChange={(value) => setAccessType(value as AccessType)}
                  className="w-full"
                >
                  <SelectItem value="browser">Browser Access (Recommended)</SelectItem>
                  <SelectItem value="cli">CLI Access</SelectItem>
                </Select>
              </>
            )}
            {accessType === "cli" && (
              <>
                <FormLabel label="CLI Command" className="mt-4" />
                <div className="flex gap-2">
                  <Input value={command} isDisabled />
                  <IconButton
                    ariaLabel="copy"
                    variant="outline_bg"
                    colorSchema="secondary"
                    onClick={handleCliAccess}
                    className="w-10"
                  >
                    <FontAwesomeIcon icon={faCopy} />
                  </IconButton>
                </div>
                <a
                  href="https://infisical.com/docs/cli/overview"
                  target="_blank"
                  className="mt-2 flex h-4 w-fit items-center gap-2 border-b border-mineshaft-400 text-sm text-mineshaft-400 transition-colors duration-100 hover:border-yellow-400 hover:text-yellow-400"
                  rel="noreferrer"
                >
                  <span>Install the Infisical CLI</span>
                  <FontAwesomeIcon icon={faUpRightFromSquare} className="size-3" />
                </a>
              </>
            )}

            {accessType === "browser" && supportsBrowserAccess && (
              <div className="mt-4">
                <Button
                  leftIcon={<FontAwesomeIcon icon={faGlobe} />}
                  onClick={handleBrowserAccess}
                  isLoading={isAccessing}
                  colorSchema="primary"
                  className="w-full"
                >
                  Open Database Browser
                </Button>
                <p className="mt-2 text-sm text-mineshaft-400">
                  Access your PostgreSQL database directly in the browser with a SQL query interface.
                </p>
              </div>
            )}
          </>
        )}
      </ModalContent>
    </Modal>
  );
};
