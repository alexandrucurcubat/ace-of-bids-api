import {
  forwardRef,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { IUser } from 'src/user/models/user.interface';
import { UserEntity } from 'src/user/models/user.entity';
import { RegisterDto } from '../models/dto/register.dto';
import { LoginDto } from '../models/dto/login.dto';
import { IJwtResponse } from '../models/jwt-response.interface';
import { UserService } from 'src/user/services/user.service';
import { UpdatePasswordDto } from 'src/auth/models/dto/update-password.dto';
import { UpdateUsernameDto } from 'src/auth/models/dto/update-username.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
    @Inject(forwardRef(() => UserService))
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto) {
    const email = registerDto.email;
    const username = registerDto.username;
    const password = registerDto.password;
    if (!(await this.emailExists(email))) {
      if (!(await this.usernameExists(username))) {
        registerDto.password = await this.hashPassword(password);
        const user = (await this.userRepository.save(registerDto)) as IUser;
        delete user.password;
        return user;
      } else {
        throw new HttpException('username exists', HttpStatus.CONFLICT);
      }
    } else {
      throw new HttpException('email exists', HttpStatus.CONFLICT);
    }
  }

  async login(loginDto: LoginDto) {
    const email = loginDto.email;
    const password = loginDto.password;
    const user = await this.findUserByEmail(email);
    if (user) {
      if (await this.validatePassword(password, user.password)) {
        delete user.password;
        return { jwt: await this.generateJwt(user) } as IJwtResponse;
      } else {
        throw new HttpException('invalid credentials', HttpStatus.UNAUTHORIZED);
      }
    } else {
      throw new HttpException('invalid credentials', HttpStatus.UNAUTHORIZED);
    }
  }

  async updateUsername(id: number, updateUsernameDto: UpdateUsernameDto) {
    const username = updateUsernameDto.username;
    const password = updateUsernameDto.password;
    const user = await this.userService.findUserById(id);
    if (await this.validatePassword(password, user.password)) {
      if (user.username !== username) {
        if (await this.usernameExists(username)) {
          throw new HttpException('username exists', HttpStatus.CONFLICT);
        } else {
          await this.userRepository.update(id, { username });
          const updatedUser = await this.userService.findUserById(id);
          updatedUser.jwt = await this.generateJwt(updatedUser);
          delete updatedUser.password;
          return updatedUser;
        }
      } else {
        delete user.password;
        return user;
      }
    } else {
      throw new HttpException('invalid credentials', HttpStatus.UNAUTHORIZED);
    }
  }

  async updatePassword(id: number, updatePasswordDto: UpdatePasswordDto) {
    const newPassword = updatePasswordDto.newPassword;
    const oldPassword = updatePasswordDto.oldPassword;
    const user = await this.userService.findUserById(id);
    if (await this.validatePassword(oldPassword, user.password)) {
      this.userRepository.update(id, {
        password: await this.hashPassword(newPassword),
      });
      delete user.password;
      return user;
    } else {
      throw new HttpException('invalid credentials', HttpStatus.UNAUTHORIZED);
    }
  }

  private findUserByEmail(email: string) {
    return this.userRepository.findOne(
      { email },
      { select: ['id', 'email', 'username', 'password'] },
    ) as Promise<IUser>;
  }

  private async emailExists(email: string) {
    return (await this.userRepository.findOne({ email })) ? true : false;
  }

  private async usernameExists(username: string) {
    return (await this.userRepository.findOne({ username })) ? true : false;
  }

  private generateJwt(user: IUser) {
    return this.jwtService.signAsync({ user });
  }

  private validatePassword(password: string, storedPasswordHash: string) {
    return this.comparePasswords(password, storedPasswordHash);
  }

  private comparePasswords(password: string, storedPasswordHash: string) {
    return bcrypt.compare(password, storedPasswordHash);
  }

  private hashPassword(password: string) {
    return bcrypt.hash(password, 12);
  }
}
