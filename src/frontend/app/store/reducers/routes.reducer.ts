import { AppState, IRequestEntityTypeState } from '../app-state';
import { Action } from '@ngrx/store';
import { APIResource } from '../types/api.types';
import { RouteEvents, UnmapRoute } from '../actions/route.actions';
import { APISuccessOrFailedAction } from '../types/request.types';
import { IRoute } from '../../core/cf-api.types';
import { ASSIGN_ROUTE_SUCCESS, AssociateRouteWithAppApplication } from '../actions/application-service-routes.actions';

export function routeReducer(state: IRequestEntityTypeState<APIResource<IRoute>>, action: APISuccessOrFailedAction) {
  switch (action.type) {
    case ASSIGN_ROUTE_SUCCESS:
      const mapRouteAction = action.apiAction as AssociateRouteWithAppApplication;
      const addAppRoute = state[mapRouteAction.routeGuid];
      return {
        ...state,
        [mapRouteAction.routeGuid]: {
          ...addAppRoute,
          entity: addAppFromRoute(addAppRoute.entity, mapRouteAction.guid),
        }
      };
    case RouteEvents.UNMAP_ROUTE_SUCCESS:
      const unmapRouteAction = action.apiAction as UnmapRoute;
      const removeAppRoute = state[unmapRouteAction.routeGuid];
      return {
        ...state,
        [unmapRouteAction.routeGuid]: {
          ...removeAppRoute,
          entity: removeAppFromRoute(removeAppRoute.entity, unmapRouteAction.appGuid),
        }
      };
    default:
      return state;
  }
}

function addAppFromRoute(entity: IRoute, appGuid: string) {
  const oldApps = entity.apps ? entity.apps : [];
  return {
    ...entity,
    apps: [...oldApps, appGuid]
  };
}

function removeAppFromRoute(entity: any, appGuid: string) {
  return entity.apps ? {
    ...entity,
    apps: entity.apps.filter((app: string) => app !== appGuid)
  } : entity;
}

