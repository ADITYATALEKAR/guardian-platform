import { Layer5ApiConnector } from "../../data_source/data_connector_to_ui";
import { Layer5DataSource } from "../../data_source/master_data_connector_to_layer4";

const baseUrl = String(window.location.origin).trim();
const connector = new Layer5ApiConnector(baseUrl);
export const dataSource = new Layer5DataSource(connector);
export { Layer5ApiError } from "../../data_source/data_connector_to_ui";
export type { ScanStatus, SessionState } from "../../data_source/master_data_connector_to_layer4";
