import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth } from '@nestjs/swagger';
import { Observable } from 'rxjs';

import { UserService } from '../services/user.service';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { IUser } from '../models/user.interface';
import { UpdateUserDto } from '../models/dto/update-user.dto';
import { IsOwnerGuard } from 'src/auth/guards/is-owner.guard';

@Controller('users')
export class UserController {
  constructor(private userService: UserService) {}

  @UseGuards(JwtAuthGuard, IsOwnerGuard)
  @Post('update/:id')
  @HttpCode(200)
  @ApiBearerAuth()
  updateUser(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
  ): Observable<IUser> {
    return this.userService.updateOne(id, updateUserDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get()
  @HttpCode(200)
  @ApiBearerAuth()
  // @HasRoles('admin')
  findAll(): Observable<IUser[]> {
    return this.userService.findAllUsers();
  }
}
