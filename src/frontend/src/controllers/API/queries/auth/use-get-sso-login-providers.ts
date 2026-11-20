import type { useQueryFunctionType } from "@/types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface SSOLoginProvider {
  slug: string;
  display_name: string;
}

export const useGetSsoLoginProviders: useQueryFunctionType<
  undefined,
  SSOLoginProvider[]
> = (options) => {
  const { query } = UseRequestProcessor();

  const getSsoLoginProviders = async (): Promise<SSOLoginProvider[]> => {
    const response = await api.get<SSOLoginProvider[]>(
      `${getURL("SSO")}/providers`,
    );
    return response.data;
  };

  return query(["useGetSsoLoginProviders"], getSsoLoginProviders, {
    refetchOnWindowFocus: false,
    retry: false,
    ...options,
  });
};
