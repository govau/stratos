
import { Component, OnDestroy, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormGroup, ValidatorFn, Validators } from '@angular/forms';
import { ErrorStateMatcher, MatSnackBar, ShowOnDirtyErrorStateMatcher } from '@angular/material';
import { Subscription } from 'rxjs/Rx';
import { UserProfileInfo, UserProfileInfoUpdates } from '../../../store/types/user-profile.types';
import { UserProfileService } from '../user-profile.service';
import { first } from 'rxjs/operators';


@Component({
  selector: 'app-edit-profile-info',
  templateUrl: './edit-profile-info.component.html',
  styleUrls: ['./edit-profile-info.component.scss'],
  providers: [
    { provide: ErrorStateMatcher, useClass: ShowOnDirtyErrorStateMatcher }
  ]
})
export class EditProfileInfoComponent implements OnInit, OnDestroy {

  editProfileForm: FormGroup;

  constructor(
    private userProfileService: UserProfileService,
    private fb: FormBuilder,
    private snackBar: MatSnackBar
  ) {
    this.editProfileForm = this.fb.group({
      givenName: '',
      familyName: '',
      emailAddress: '',
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
    });
  }

  private sub: Subscription;

  private error = false;

  private profile: UserProfileInfo;

  private lastRequired = false;
  private lastHavePassword = false;

  private emailAddress: string;

  private errorSnack;

  // Wire up to permissions and only allow password change if user has the 'password.write' group
  private canChangePassword = true;

  private passwordRequired = false;

  ngOnInit() {
    this.userProfileService.fetchUserProfile();
    this.userProfileService.userProfile$.pipe(first()).subscribe(profile => {
      this.profile = profile;
      this.emailAddress = this.userProfileService.getPrimaryEmailAddress(profile);
      this.editProfileForm.setValue({
        givenName: profile.name.givenName,
        familyName: profile.name.familyName,
        emailAddress: this.userProfileService.getPrimaryEmailAddress(profile),
        currentPassword: '',
        newPassword: '',
        confirmPassword: '',
      });
    });
    this.onChanges();
  }

  ngOnDestroy() {
    this.sub.unsubscribe();
    if (this.errorSnack) {
      this.snackBar.dismiss();
    }
  }

  onChanges() {
    this.sub = this.editProfileForm.valueChanges.subscribe(values => {
      const required = values.emailAddress !== this.emailAddress || values.newPassword.length;
      this.passwordRequired = !!required;
      if (required !== this.lastRequired) {
        this.lastRequired = required;
        const validators = required ? [Validators.required] : [];
        this.editProfileForm.controls['currentPassword'].setValidators(validators);
        this.editProfileForm.controls['currentPassword'].updateValueAndValidity();
      }
      const havePassword = !!values.newPassword.length;
      if (havePassword !== this.lastHavePassword) {
        this.lastHavePassword = havePassword;
        const confirmValidator = havePassword ? [Validators.required, this.confirmPasswordValidator()] : [];
        this.editProfileForm.controls['confirmPassword'].setValidators(confirmValidator);
        this.editProfileForm.controls['confirmPassword'].updateValueAndValidity();
      }
    });
  }

  confirmPasswordValidator(): ValidatorFn {
    return (control: AbstractControl): { [key: string]: any } => {
      const same = control.value === this.editProfileForm.value.newPassword;
      return same ? null : { 'passwordMatch': { value: control.value } };
    };
  }

  // Declared this way to ensure bound to this correctly
  updateProfile = () => {
    const updates: UserProfileInfoUpdates = {};
    // We will only send the values that were actually edited
    for (const key of Object.keys(this.editProfileForm.value)) {
      if (!this.editProfileForm.controls[key].pristine) {
        updates[key] = this.editProfileForm.value[key];
      }
    }
    const obs$ = this.userProfileService.updateProfile(this.profile, updates);
    return obs$.take(1).map(([profileErr, passwordErr]) => {
      const okay = !profileErr && !passwordErr;
      this.error = !okay;
      if (!okay) {
        const msg = 'An error occured updating your profie';
        this.errorSnack = this.snackBar.open(msg, 'Dismiss');
      }
      return {
        success: okay,
        redirect: okay
      };
    });
  }
}
