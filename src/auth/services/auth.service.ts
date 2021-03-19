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
import {
  EMAIL_EXISTS,
  INVALID_CREDENTIALS,
  USERNAME_EXISTS,
} from 'src/utils/exception-constants';

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
    if (await this.emailExists(email))
      throw new HttpException(EMAIL_EXISTS, HttpStatus.CONFLICT);
    if (await this.usernameExists(username))
      throw new HttpException(USERNAME_EXISTS, HttpStatus.CONFLICT);
    registerDto.password = await this.hashPassword(password);
    const user = (await this.userRepository.save(registerDto)) as IUser;
    delete user.password;
    return user;
  }

  async login(loginDto: LoginDto) {
    const email = loginDto.email;
    const password = loginDto.password;
    const user = await this.findUserByEmail(email);
    if (!user)
      throw new HttpException(INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    if (!(await this.passwordMatches(password, user.password)))
      throw new HttpException(INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    delete user.password;
    return { jwt: await this.generateJwt(user) } as IJwtResponse;
  }

  async updateUsername(id: number, updateUsernameDto: UpdateUsernameDto) {
    const username = updateUsernameDto.username;
    const password = updateUsernameDto.password;
    const user = await this.userService.findUserById(id);
    if (!(await this.passwordMatches(password, user.password)))
      throw new HttpException(INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    if (user.username === username) {
      delete user.password;
      return user;
    }
    if (await this.usernameExists(username))
      throw new HttpException(USERNAME_EXISTS, HttpStatus.CONFLICT);
    await this.userRepository.update(id, { username });
    const updatedUser = await this.userService.findUserById(id);
    updatedUser.jwt = await this.generateJwt(updatedUser);
    delete updatedUser.password;
    return updatedUser;
  }

  async updatePassword(id: number, updatePasswordDto: UpdatePasswordDto) {
    const newPassword = updatePasswordDto.newPassword;
    const oldPassword = updatePasswordDto.oldPassword;
    const user = await this.userService.findUserById(id);
    if (!(await this.passwordMatches(oldPassword, user.password)))
      throw new HttpException(INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    this.userRepository.update(id, {
      password: await this.hashPassword(newPassword),
    });
    delete user.password;
    return user;
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

  private passwordMatches(password: string, storedPasswordHash: string) {
    return bcrypt.compare(password, storedPasswordHash);
  }

  private hashPassword(password: string) {
    return bcrypt.hash(password, 12);
  }

  private generateJwt(user: IUser) {
    return this.jwtService.signAsync({ user });
  }
}
