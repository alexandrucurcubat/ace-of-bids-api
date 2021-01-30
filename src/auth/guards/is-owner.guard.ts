import {
  CanActivate,
  ExecutionContext,
  forwardRef,
  Inject,
  Injectable,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

import { IUser } from 'src/user/models/user.interface';
import { UserService } from 'src/user/services/user.service';

@Injectable()
export class IsOwnerGuard implements CanActivate {
  constructor(
    @Inject(forwardRef(() => UserService))
    private userService: UserService,
  ) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    const params = request.params;
    const user: IUser = request.user;

    return this.userService.findOne(user.id).pipe(
      map((user: IUser) => {
        const isAuthorized = user.id === +params.id;
        return user && isAuthorized;
      }),
    );
  }
}
