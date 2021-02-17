import {
  CanActivate,
  ExecutionContext,
  forwardRef,
  Inject,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

import { IUser } from 'src/user/models/user.interface';
import { UserService } from 'src/user/services/user.service';

@Injectable()
export class HasRolesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    @Inject(forwardRef(() => UserService))
    private userService: UserService,
  ) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const requiredRoles = this.reflector.get<string[]>(
      'roles',
      context.getHandler(),
    );
    if (!requiredRoles) {
      return true;
    }
    const request = context.switchToHttp().getRequest();
    const user: IUser = request.user;

    return this.userService.findUserById(user.id).pipe(
      map((user: IUser) => {
        const isAuthorized = requiredRoles.indexOf(user.role) > -1;
        return user && isAuthorized;
      }),
    );
  }
}
