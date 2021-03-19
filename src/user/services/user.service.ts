import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { UserEntity } from '../models/user.entity';
import { IUser } from '../models/user.interface';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
  ) {}

  findUserById(id: number) {
    return this.userRepository.findOne(
      { id },
      { select: ['id', 'email', 'username', 'password', 'role'] },
    ) as Promise<IUser>;
  }

  findAllUsers() {
    return this.userRepository.find() as Promise<IUser[]>;
  }
}
