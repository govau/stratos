import { Injectable } from '@angular/core';
import { MatDialog } from '@angular/material';
import { Store } from '@ngrx/store';

import {
  ConnectEndpointDialogComponent,
} from '../../../../../features/endpoints/connect-endpoint-dialog/connect-endpoint-dialog.component';
import { getFullEndpointApiUrl, getNameForEndpointType } from '../../../../../features/endpoints/endpoint-helpers';
import { DisconnectEndpoint, UnregisterEndpoint } from '../../../../../store/actions/endpoint.actions';
import { ShowSnackBar } from '../../../../../store/actions/snackBar.actions';
import { GetSystemInfo } from '../../../../../store/actions/system.actions';
import { AppState } from '../../../../../store/app-state';
import { EndpointsEffect } from '../../../../../store/effects/endpoint.effects';
import { selectDeletionInfo, selectUpdateInfo } from '../../../../../store/selectors/api.selectors';
import { EndpointModel, endpointStoreNames } from '../../../../../store/types/endpoint.types';
import { EntityMonitorFactory } from '../../../../monitors/entity-monitor.factory.service';
import { InternalEventMonitorFactory } from '../../../../monitors/internal-event-monitor.factory';
import { PaginationMonitorFactory } from '../../../../monitors/pagination-monitor.factory';
import { ITableColumn } from '../../list-table/table.types';
import { IListAction, IListConfig, ListViewTypes } from '../../list.component.types';
import { EndpointsDataSource } from './endpoints-data-source';
import { TableCellEndpointNameComponent } from './table-cell-endpoint-name/table-cell-endpoint-name.component';
import { TableCellEndpointStatusComponent } from './table-cell-endpoint-status/table-cell-endpoint-status.component';
import { Observable } from 'rxjs/Observable';


function getEndpointTypeString(endpoint: EndpointModel): string {
  return getNameForEndpointType(endpoint.cnsi_type);
}

export const endpointColumns: ITableColumn<EndpointModel>[] = [
  {
    columnId: 'name',
    headerCell: () => 'Name',
    cellComponent: TableCellEndpointNameComponent,
    sort: {
      type: 'sort',
      orderKey: 'name',
      field: 'name'
    },
    cellFlex: '2'
  },
  {
    columnId: 'connection',
    headerCell: () => 'Status',
    cellComponent: TableCellEndpointStatusComponent,
    sort: {
      type: 'sort',
      orderKey: 'connection',
      field: 'info.user'
    },
    cellFlex: '1'
  },
  {
    columnId: 'type',
    headerCell: () => 'Type',
    cellDefinition: {
      getValue: getEndpointTypeString
    },
    sort: {
      type: 'sort',
      orderKey: 'type',
      field: 'cnsi_type'
    },
    cellFlex: '2'
  },
  {
    columnId: 'address',
    headerCell: () => 'Address',
    cellDefinition: {
      getValue: getFullEndpointApiUrl
    },
    sort: {
      type: 'sort',
      orderKey: 'address',
      field: 'api_endpoint.Host'
    },
    cellFlex: '5'
  },
];

@Injectable()
export class EndpointsListConfigService implements IListConfig<EndpointModel> {
  private listActionDelete: IListAction<EndpointModel> = {
    action: (item) => {
      this.store.dispatch(new UnregisterEndpoint(item.guid, item.cnsi_type));
      this.handleDeleteAction(item, ([oldVal, newVal]) => {
        this.store.dispatch(new ShowSnackBar(`Unregistered ${item.name}`));
      });
    },
    label: 'Unregister',
    description: 'Remove the endpoint'
  };

  private listActionDisconnect: IListAction<EndpointModel> = {
    action: (item) => {
      this.store.dispatch(new DisconnectEndpoint(item.guid, item.cnsi_type));
      this.handleUpdateAction(item, EndpointsEffect.disconnectingKey, ([oldVal, newVal]) => {
        this.store.dispatch(new ShowSnackBar(`Disconnected ${item.name}`));
        this.store.dispatch(new GetSystemInfo());
      });
    },
    label: 'Disconnect',
    description: ``, // Description depends on console user permission
    createVisible: (row: EndpointModel) => Observable.of(row.connectionStatus === 'connected'),
    createEnabled: (row: EndpointModel) => Observable.of(true),
  };

  private listActionConnect: IListAction<EndpointModel> = {
    action: (item) => {
      const dialogRef = this.dialog.open(ConnectEndpointDialogComponent, {
        data: {
          name: item.name,
          guid: item.guid,
          type: item.cnsi_type,
        },
        disableClose: true
      });
    },
    label: 'Connect',
    description: '',
    createVisible: (row: EndpointModel) => Observable.of(row.connectionStatus === 'disconnected'),
    createEnabled: (row: EndpointModel) => Observable.of(true),
  };

  private singleActions = [
    this.listActionDisconnect,
    this.listActionConnect,
    this.listActionDelete
  ];

  private globalActions = [];

  columns = endpointColumns;
  isLocal = true;
  dataSource: EndpointsDataSource;
  viewType = ListViewTypes.TABLE_ONLY;
  text = {
    title: '',
    filter: 'Filter Endpoints'
  };
  enableTextFilter = true;
  tableFixedRowHeight = true;

  private handleUpdateAction(item, effectKey, handleChange) {
    this.handleAction(selectUpdateInfo(
      endpointStoreNames.type,
      item.guid,
      effectKey,
    ), handleChange);
  }

  private handleDeleteAction(item, handleChange) {
    this.handleAction(selectDeletionInfo(
      endpointStoreNames.type,
      item.guid,
    ), handleChange);
  }

  private handleAction(storeSelect, handleChange) {
    const disSub = this.store.select(storeSelect)
      .pairwise()
      .subscribe(([oldVal, newVal]) => {
        // https://github.com/SUSE/stratos/issues/29 Generic way to handle errors ('Failed to disconnect X')
        if (!newVal.error && (oldVal.busy && !newVal.busy)) {
          handleChange([oldVal, newVal]);
          disSub.unsubscribe();
        }
      });
  }

  constructor(
    private store: Store<AppState>,
    private dialog: MatDialog,
    private paginationMonitorFactory: PaginationMonitorFactory,
    private entityMonitorFactory: EntityMonitorFactory,
    private internalEventMonitorFactory: InternalEventMonitorFactory
  ) {
    this.dataSource = new EndpointsDataSource(
      this.store,
      this,
      paginationMonitorFactory,
      entityMonitorFactory,
      internalEventMonitorFactory
    );
  }

  public getGlobalActions = () => this.globalActions;
  public getMultiActions = () => [];
  public getSingleActions = () => this.singleActions;
  public getColumns = () => this.columns;
  public getDataSource = () => this.dataSource;
  public getMultiFiltersConfigs = () => [];
}
