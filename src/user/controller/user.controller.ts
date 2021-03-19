import { Controller, Get, HttpCode, UseGuards } from '@nestjs/common';
import { ApiBearerAuth } from '@nestjs/swagger';

import { UserService } from '../services/user.service';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';

@Controller('users')
export class UserController {
  constructor(private userService: UserService) {}

  @UseGuards(JwtAuthGuard)
  @Get()
  @HttpCode(200)
  @ApiBearerAuth()
  // @HasRoles('admin')
  findAll() {
    return this.userService.findAllUsers();
  }
}
