import { render, screen } from "@testing-library/react";
import CustomLoginSsoOptions from "../custom-login-sso-options";

const mockUseGetSsoLoginProviders = jest.fn();

jest.mock("@/controllers/API/queries/auth", () => ({
  useGetSsoLoginProviders: () => mockUseGetSsoLoginProviders(),
}));

describe("CustomLoginSsoOptions", () => {
  beforeEach(() => {
    window.history.pushState({}, "", "/login?redirect=%2Fflow%2Fexample");
    mockUseGetSsoLoginProviders.mockReturnValue({ data: [] });
  });

  it("does not render when no browser SSO provider is enabled", () => {
    render(<CustomLoginSsoOptions />);

    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });

  it("links each provider to its safe browser login endpoint", () => {
    mockUseGetSsoLoginProviders.mockReturnValue({
      data: [{ slug: "keycloak", display_name: "Keycloak" }],
    });

    render(<CustomLoginSsoOptions />);

    expect(
      screen.getByRole("link", { name: "Continue with Keycloak" }),
    ).toHaveAttribute(
      "href",
      "/api/v1/sso/keycloak/login?next=%2Fflow%2Fexample",
    );
  });
});
