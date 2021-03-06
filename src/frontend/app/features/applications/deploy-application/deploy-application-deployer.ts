import { HttpClient } from '@angular/common/http';
import { Store } from '@ngrx/store';
import { QueueingSubject } from 'queueing-subject/lib';
import websocketConnect from 'rxjs-websockets';
import { BehaviorSubject } from 'rxjs/BehaviorSubject';
import { Observable } from 'rxjs/Observable';
import { catchError, filter, first, map, mergeMap, share, tap } from 'rxjs/operators';
import { Subscription } from 'rxjs/Subscription';

import { environment } from '../../../../environments/environment';
import { CfOrgSpaceDataService } from '../../../shared/data-services/cf-org-space-service.service';
import { AppState } from '../../../store/app-state';
import { organizationSchemaKey, spaceSchemaKey } from '../../../store/helpers/entity-factory';
import { selectEntity } from '../../../store/selectors/api.selectors';
import { selectDeployAppState } from '../../../store/selectors/deploy-application.selector';
import { AppData, DeployApplicationSource, SocketEventTypes } from '../../../store/types/deploy-application.types';
import { FileScannerInfo } from './deploy-application-step2/deploy-application-fs/deploy-application-fs-scanner';

export interface DeployApplicationDeployerStatus {
  error: boolean;
  errorMsg?: string;
  deploying: boolean;
}

export interface FileTransferStatus {
  totalFiles: number;
  filesSent: number;
  bytesSent: number;
  totalBytes: number;
  fileName: string;
}

export class DeployApplicationDeployer {

  isRedeploy: string;
  connectSub: Subscription;
  msgSub: Subscription;
  streamTitle = 'Preparing...';
  appData: AppData;
  proxyAPIVersion = environment.proxyAPIVersion;
  appGuid: string;
  cfGuid: string;
  orgGuid: string;
  spaceGuid: string;
  applicationSource: any;

  status$ = new BehaviorSubject<DeployApplicationDeployerStatus>({
    error: false,
    deploying: false
  });

  // Status of file transfers
  fileTransferStatus$ = new BehaviorSubject<FileTransferStatus>(undefined);

  public messages: Observable<string>;

  // Are we deploying?
  deploying = false;

  private hasSentSource = false;

  private inputStream;

  private isOpen = false;

  public fsFileInfo: FileScannerInfo;

  private fileTransfers;
  private fileTransferStatus: FileTransferStatus;
  private currentFileTransfer;

  constructor(
    private store: Store<AppState>,
    public cfOrgSpaceService: CfOrgSpaceDataService,
    private http: HttpClient,
  ) { }

  updateStatus(error = false, errorMsg?: string) {
    this.status$.next({
      error: error,
      errorMsg: errorMsg,
      deploying: this.deploying
    });
  }

  close() {
    // Unsubscribe from the websocket stream
    if (this.msgSub) {
      this.msgSub.unsubscribe();
    }
    if (this.connectSub) {
      this.connectSub.unsubscribe();
    }
    this.isOpen = false;
    this.currentFileTransfer = undefined;
  }

  open() {
    if (this.isOpen) {
      return;
    }

    const readyFilter = this.fsFileInfo ? () => true :
      (appDetail) => !!appDetail.applicationSource && !!appDetail.applicationSource.projectName;
    this.isOpen = true;
    this.connectSub = this.store.select(selectDeployAppState).pipe(
      filter(appDetail => !!appDetail.cloudFoundryDetails && readyFilter(appDetail)),
      mergeMap(appDetails => {
        const orgSubscription = this.store.select(selectEntity(organizationSchemaKey, appDetails.cloudFoundryDetails.org));
        const spaceSubscription = this.store.select(selectEntity(spaceSchemaKey, appDetails.cloudFoundryDetails.space));
        return Observable.of(appDetails).combineLatest(orgSubscription, spaceSubscription);
      }),
      first(),
      tap(([appDetail, org, space]) => {
        this.cfGuid = appDetail.cloudFoundryDetails.cloudFoundry;
        this.orgGuid = appDetail.cloudFoundryDetails.org;
        this.spaceGuid = appDetail.cloudFoundryDetails.space;
        this.applicationSource = appDetail.applicationSource;
        const host = window.location.host;
        const streamUrl = (
          `wss://${host}/pp/${this.proxyAPIVersion}/${this.cfGuid}/${this.orgGuid}/${this.spaceGuid}/deploy` +
          `?org=${org.entity.name}&space=${space.entity.name}`
        );

        this.inputStream = new QueueingSubject<string>();
        this.messages = websocketConnect(streamUrl, this.inputStream)
          .messages.pipe(
            catchError(e => {
              return [];
            }),
            share(),
            map(message => {
              const json = JSON.parse(message);
              return json;
            }),
            filter(l => !!l),
            tap((log) => {
              // Deal with control messages
              if (log.type !== SocketEventTypes.DATA) {
                this.processWebSocketMessage(log);
              }
            }),
            filter((log) => log.type === SocketEventTypes.DATA),
            map((log) => log.message)
          );
        this.msgSub = this.messages.subscribe();
      })
    ).subscribe();
  }

  deploy() {
    // After the source has been sent, acknowledge the wait
    const msg = {
      message: '',
      timestamp: Math.round((new Date()).getTime() / 1000),
      type: SocketEventTypes.SOURCE_WAIT_ACK
    };
    this.inputStream.next(JSON.stringify(msg));
  }

  sendProjectInfo = (appSource: DeployApplicationSource) => {
    if (appSource.type.id === 'git') {
      if (appSource.type.subType === 'github') {
        return this.sendGitHubSourceMetadata(appSource);
      }
      if (appSource.type.subType === 'giturl') {
        return this.sendGitUrlSourceMetadata(appSource);
      }
    } else if (appSource.type.id === 'fs') {
      return this.sendLocalSourceMetadata();
    }
    return '';
  }

  sendGitHubSourceMetadata = (appSource: DeployApplicationSource) => {
    const github = {
      project: appSource.projectName,
      branch: appSource.branch.name,
      type: appSource.type.subType,
      commit: appSource.commit
    };

    const msg = {
      message: JSON.stringify(github),
      timestamp: Math.round((new Date()).getTime() / 1000),
      type: SocketEventTypes.SOURCE_GITHUB
    };
    return JSON.stringify(msg);
  }

  sendGitUrlSourceMetadata = (appSource: DeployApplicationSource) => {
    const gitUrl = {
      url: appSource.projectName,
      branch: appSource.branch.name,
      type: appSource.type.subType
    };

    const msg = {
      message: JSON.stringify(gitUrl),
      timestamp: Math.round((new Date()).getTime() / 1000),
      type: SocketEventTypes.SOURCE_GITURL
    };
    return JSON.stringify(msg);
  }

  processWebSocketMessage = (log) => {
    switch (log.type) {
      case SocketEventTypes.MANIFEST:
        this.streamTitle = 'Starting deployment...';
        // This info is will be used to retrieve the app Id
        this.appData = JSON.parse(log.message).Applications[0];
        break;
      case SocketEventTypes.EVENT_PUSH_STARTED:
        this.streamTitle = 'Deploying...';
        this.deploying = true;
        this.updateStatus();
        break;
      case SocketEventTypes.EVENT_PUSH_COMPLETED:
        // Done
        this.streamTitle = 'Deployed';
        this.deploying = false;
        this.updateStatus();
        break;
      case SocketEventTypes.CLOSE_SUCCESS:
        this.onClose(log, null, null);
        break;
      case SocketEventTypes.CLOSE_INVALID_MANIFEST:
        this.onClose(log, 'Deploy Failed - Invalid manifest!',
          'Failed to deploy app! Please make sure that a valid manifest.yaml was provided!');
        break;
      case SocketEventTypes.CLOSE_NO_MANIFEST:
        this.onClose(log, 'Deploy Failed - No manifest present!',
          'Failed to deploy app! Please make sure that a valid manifest.yaml is present!');
        break;
      case SocketEventTypes.CLOSE_FAILED_CLONE:
        this.onClose(log, 'Deploy Failed - Failed to clone repository!',
          'Failed to deploy app! Please make sure the repository is public!');
        break;
      case SocketEventTypes.CLOSE_FAILED_NO_BRANCH:
        this.onClose(log, 'Deploy Failed - Failed to located branch!',
          'Failed to deploy app! Please make sure that branch exists!');
        break;
      case SocketEventTypes.CLOSE_FAILURE:
      case SocketEventTypes.CLOSE_PUSH_ERROR:
      case SocketEventTypes.CLOSE_NO_SESSION:
      case SocketEventTypes.CLOSE_NO_CNSI:
      case SocketEventTypes.CLOSE_NO_CNSI_USERTOKEN:
        this.onClose(log, 'Deploy Failed!',
          'Failed to deploy app!');
        break;
      case SocketEventTypes.SOURCE_REQUIRED:
        this.inputStream.next(this.sendProjectInfo(this.applicationSource));
        break;
      case SocketEventTypes.EVENT_CLONED:
      case SocketEventTypes.EVENT_FETCHED_MANIFEST:
      case SocketEventTypes.MANIFEST:
        break;
      case SocketEventTypes.SOURCE_FILE_ACK:
        this.sendNextFile();
        break;
      default:
      // noop
    }
  }

  private sendNextFile() {
    // Update for the previous file transfer
    if (this.currentFileTransfer) {
      this.fileTransferStatus.bytesSent += this.currentFileTransfer.size;
      this.fileTransferStatus.filesSent++;
      this.fileTransferStatus$.next(this.fileTransferStatus);
    }

    if (this.fileTransfers.length > 0) {
      const file = this.fileTransfers.shift();

      // Send file metadata
      const msg = {
        message: file.fullPath,
        timestamp: Math.round((new Date()).getTime() / 1000),
        type: SocketEventTypes.SOURCE_FILE
      };

      this.fileTransferStatus.fileName = file.fullPath;
      this.fileTransferStatus$.next(this.fileTransferStatus);

      // Send the file name metadata
      this.inputStream.next(JSON.stringify(msg));

      // Now send the file data as a binary message
      const reader = new FileReader();
      reader.onload = () => {
        this.currentFileTransfer = file;
        const output = reader.result;
        this.inputStream.next(output);
      };
      reader.readAsArrayBuffer(file);
    }
  }

  private onClose(log, title, error) {
    if (title) {
      this.streamTitle = title;
    }
    this.deploying = false;
    this.updateStatus(
      error,
      error ? `${error}\nReason: ${log.message}` : undefined
    );
  }

  // File Upload
  sendLocalSourceMetadata() {
    const metadata = {
      files: [],
      folders: []
    };

    this.collectFoldersAndFiles(metadata, null, this.fsFileInfo.root);

    this.fileTransfers = metadata.files;
    this.fileTransferStatus = {
      totalFiles: metadata.files.length,
      filesSent: 0,
      bytesSent: 0,
      totalBytes: this.fsFileInfo.total,
      fileName: ''
    };

    this.fileTransferStatus$.next(this.fileTransferStatus);

    const transferMetadata = {
      files: metadata.files.length,
      folders: metadata.folders,
      type: 'filefolder',
      wait: true
    };

    // Send the source metadata
    return JSON.stringify({
      message: JSON.stringify(transferMetadata),
      timestamp: Math.round((new Date()).getTime() / 1000),
      type: SocketEventTypes.SOURCE_FOLDER
    });
  }

  // Flatten files and folders
  collectFoldersAndFiles(metadata, base, folder) {
    if (folder.files) {
      folder.files.forEach(file => {
        file.fullPath = base ? base + '/' + file.name : file.name;
        metadata.files.push(file);
      });
    }

    if (folder.folders) {
      Object.keys(folder.folders).forEach(name => {
        const sub = folder.folders[name];
        const fullPath = base ? base + '/' + name : name;
        metadata.folders.push(fullPath);
        this.collectFoldersAndFiles(metadata, fullPath, sub);
      });
    }
  }
}
