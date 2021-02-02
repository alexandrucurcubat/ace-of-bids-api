import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { from, Observable, throwError } from 'rxjs';
import { catchError, map, switchMap } from 'rxjs/operators';

import { UserEntity } from '../models/user.entity';
import { IUser } from '../models/user.interface';
import { UpdateUserDto } from '../models/dto/update-user.dto';
import { AuthService } from 'src/auth/services/auth.service';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
    private authService: AuthService,
  ) {}

  updateOne(id: string, updateUserDto: UpdateUserDto): Observable<IUser> {
    const newUsername = updateUserDto.username;
    const newPassword = updateUserDto.newPassword;
    return this.authService.usernameExists(newUsername).pipe(
      switchMap((usernameExists: boolean) => {
        if (!usernameExists) {
          return this.findUserById(+id).pipe(
            switchMap((user: IUser) => {
              if (user) {
                return this.authService
                  .validatePassword(updateUserDto.oldPassword, user.password)
                  .pipe(
                    switchMap((oldPasswordMatches: boolean) => {
                      if (oldPasswordMatches) {
                        if (newPassword) {
                          return this.authService
                            .hashPassword(newPassword)
                            .pipe(
                              switchMap((hashedPassword: string) => {
                                return from(
                                  this.userRepository.update(+id, {
                                    username: newUsername,
                                    password: hashedPassword,
                                  }),
                                )
                                  .pipe(switchMap(() => this.findUserById(+id)))
                                  .pipe(
                                    map((updatedUser: IUser) => {
                                      delete updatedUser.password;
                                      return updatedUser;
                                    }),
                                  );
                              }),
                            );
                        } else {
                          return from(
                            this.userRepository.update(+id, {
                              username: newUsername,
                            }),
                          )
                            .pipe(switchMap(() => this.findUserById(+id)))
                            .pipe(
                              map((updatedUser: IUser) => {
                                delete updatedUser.password;
                                return updatedUser;
                              }),
                            );
                        }
                      } else {
                        throw new HttpException(
                          'invalid password',
                          HttpStatus.UNAUTHORIZED,
                        );
                      }
                    }),
                  );
              } else {
                throw new HttpException('user not found', HttpStatus.NOT_FOUND);
              }
            }),
          );
        } else {
          throw new HttpException('username exists', HttpStatus.CONFLICT);
        }
      }),
    );
  }

  findUserByEmail(email: string): Observable<IUser> {
    return from(
      this.userRepository.findOne(
        { email },
        { select: ['id', 'email', 'username', 'password'] },
      ),
    );
  }

  findUserById(id: number): Observable<IUser> {
    return from(
      this.userRepository.findOne(
        { id },
        { select: ['id', 'email', 'username', 'password'] },
      ),
    ).pipe(catchError((err) => throwError(err)));
  }

  findAllUsers(): Observable<IUser[]> {
    return from(this.userRepository.find()).pipe(
      catchError((err) => throwError(err)),
    );
  }
}
