import { Injectable } from '@nestjs/common';

import { version } from 'package.json';

@Injectable()
export class AppService {
  api(): string {
    return `Ace of Bids API v(${version})`;
  }
}
