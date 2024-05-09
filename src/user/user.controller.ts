import { Controller, Get, Patch, Req, UseGuards } from '@nestjs/common';
import { User } from '@prisma/client';
import { Request } from 'express';
import { GetUser } from '../auth/decorator';
import { JwtGuard } from '../auth/guard';

@UseGuards(JwtGuard)
@Controller('users')
export class UserController {
  @Get('me')
  getUsers(@GetUser() user: User) {
    return user;
  }

  @Patch()
  editUser(@GetUser('') user: User, @Req() req: Request) {
    return user;
  }
}
