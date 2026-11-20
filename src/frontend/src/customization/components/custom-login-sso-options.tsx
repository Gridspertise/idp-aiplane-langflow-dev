import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { getURL } from "@/controllers/API/helpers/constants";
import { useGetSsoLoginProviders } from "@/controllers/API/queries/auth";

function postLoginPath(): string {
  const redirect = new URLSearchParams(window.location.search).get("redirect");
  return redirect?.startsWith("/") && !redirect.startsWith("//")
    ? redirect
    : "/home";
}

export default function CustomLoginSsoOptions() {
  const { t } = useTranslation();
  const { data: providers = [] } = useGetSsoLoginProviders();

  if (providers.length === 0) {
    return null;
  }

  const next = encodeURIComponent(postLoginPath());

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center gap-3">
        <Separator />
        <span className="text-xs text-muted-foreground">
          {t("auth.ssoDivider")}
        </span>
        <Separator />
      </div>
      {providers.map((provider) => (
        <Button
          asChild
          className="h-11 w-full rounded-lg"
          key={provider.slug}
          variant="outline"
        >
          <a
            href={`${getURL("SSO", { provider: provider.slug })}/login?next=${next}`}
          >
            {t("auth.continueWith", { provider: provider.display_name })}
          </a>
        </Button>
      ))}
    </div>
  );
}
