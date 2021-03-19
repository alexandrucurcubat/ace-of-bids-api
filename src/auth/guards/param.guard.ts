import {
  CanActivate,
  ExecutionContext,
  forwardRef,
  Inject,
  Injectable,
} from '@nestjs/common';

import { UserService } from 'src/user/services/user.service';

@Injectable()
export class ParamGuard implements CanActivate {
  constructor(
    @Inject(forwardRef(() => UserService))
    private userService: UserService,
  ) {}

  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    const user = await this.userService.findUserById(request.user.id);
    return user && user.id === +request.params.id;
  }
}
