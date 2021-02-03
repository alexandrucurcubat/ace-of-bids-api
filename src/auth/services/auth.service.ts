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
import { from, Observable, of, throwError } from 'rxjs';
import * as bcrypt from 'bcrypt';

import { IUser } from 'src/user/models/user.interface';
import { UserEntity } from 'src/user/models/user.entity';
import { RegisterDto } from '../models/dto/register.dto';
import { catchError, map, switchMap } from 'rxjs/operators';
import { LoginDto } from '../models/dto/login.dto';
import { IJwt } from '../models/jwt.interface';
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

  register(registerDto: RegisterDto): Observable<IUser> {
    return this.emailExists(registerDto.email).pipe(
      switchMap((emailExists: boolean) => {
        if (!emailExists) {
          return this.usernameExists(registerDto.username).pipe(
            switchMap((usernameExists: boolean) => {
              if (!usernameExists) {
                return this.hashPassword(registerDto.password).pipe(
                  switchMap((hashedPassword: string) => {
                    registerDto.password = hashedPassword;
                    return from(this.userRepository.save(registerDto)).pipe(
                      map((savedUser: IUser) => {
                        delete savedUser.password;
                        return savedUser;
                      }),
                      catchError((err) => throwError(err)),
                    );
                  }),
                );
              } else {
                throw new HttpException('username exists', HttpStatus.CONFLICT);
              }
            }),
          );
        } else {
          throw new HttpException('email exists', HttpStatus.CONFLICT);
        }
      }),
    );
  }

  login(loginDto: LoginDto): Observable<IJwt> {
    return this.userService.findUserByEmail(loginDto.email).pipe(
      switchMap((user: IUser) => {
        if (user) {
          return this.validatePassword(loginDto.password, user.password).pipe(
            switchMap((passwordsMatches: boolean) => {
              if (passwordsMatches) {
                delete user.password;
                return this.generateJwt(user).pipe(map((jwt) => ({ jwt })));
              } else {
                throw new HttpException(
                  'invalid credentials',
                  HttpStatus.UNAUTHORIZED,
                );
              }
            }),
          );
        } else {
          throw new HttpException(
            'invalid credentials',
            HttpStatus.UNAUTHORIZED,
          );
        }
      }),
    );
  }

  updateUsername(
    id: number,
    updateUsernameDto: UpdateUsernameDto,
  ): Observable<IUser> {
    const newUsername = updateUsernameDto.username;
    return this.userService.findUserById(id).pipe(
      switchMap((user: IUser) => {
        return this.validatePassword(
          updateUsernameDto.oldPassword,
          user.password,
        ).pipe(
          switchMap((passwordMatches: boolean) => {
            if (passwordMatches) {
              if (user.username !== newUsername) {
                return this.usernameExists(newUsername).pipe(
                  switchMap((emailExists: boolean) => {
                    if (emailExists) {
                      throw new HttpException(
                        'email exists',
                        HttpStatus.CONFLICT,
                      );
                    } else {
                      return from(
                        this.userRepository.update(id, {
                          username: newUsername,
                        }),
                      )
                        .pipe(
                          switchMap(() => this.userService.findUserById(id)),
                        )
                        .pipe(
                          switchMap((user: IUser) => {
                            return this.generateJwt(user).pipe(
                              map((jwt: string) => {
                                user.jwt = jwt;
                                delete user.password;
                                return user;
                              }),
                            );
                          }),
                        );
                    }
                  }),
                );
              } else {
                delete user.password;
                return of(user);
              }
            } else {
              throw new HttpException(
                'invalid credentials',
                HttpStatus.UNAUTHORIZED,
              );
            }
          }),
        );
      }),
    );
  }

  updatePassword(
    id: number,
    updatePasswordDto: UpdatePasswordDto,
  ): Observable<IUser> {
    const newPassword = updatePasswordDto.newPassword;
    return this.userService.findUserById(id).pipe(
      switchMap((user: IUser) => {
        return this.validatePassword(
          updatePasswordDto.oldPassword,
          user.password,
        ).pipe(
          switchMap((passwordMatches: boolean) => {
            if (passwordMatches) {
              return this.hashPassword(newPassword).pipe(
                switchMap((hashedPassword: string) => {
                  return from(
                    this.userRepository.update(id, {
                      password: hashedPassword,
                    }),
                  )
                    .pipe(switchMap(() => this.userService.findUserById(id)))
                    .pipe(
                      map((user: IUser) => {
                        delete user.password;
                        return user;
                      }),
                    );
                }),
              );
            } else {
              throw new HttpException(
                'invalid credentials',
                HttpStatus.UNAUTHORIZED,
              );
            }
          }),
        );
      }),
    );
  }

  private validatePassword(
    password: string,
    storedPasswordHash: string,
  ): Observable<boolean> {
    return this.comparePasswords(password, storedPasswordHash);
  }

  private hashPassword(password: string): Observable<string> {
    return from(bcrypt.hash(password, 12));
  }

  private usernameExists(username: string): Observable<boolean> {
    return from(this.userRepository.findOne({ username })).pipe(
      map((user: IUser) => (user ? true : false)),
    );
  }

  private emailExists(email: string): Observable<boolean> {
    return from(this.userRepository.findOne({ email })).pipe(
      map((user: IUser) => (user ? true : false)),
    );
  }

  private generateJwt(user: IUser): Observable<string> {
    return from(this.jwtService.signAsync({ user }));
  }

  private comparePasswords(
    password: string,
    storedPasswordHash: string,
  ): Observable<any> {
    return from(bcrypt.compare(password, storedPasswordHash));
  }
}
