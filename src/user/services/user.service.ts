import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { from, Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

import { UserEntity } from '../models/user.entity';
import { IUser } from '../models/user.interface';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
  ) {}

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
