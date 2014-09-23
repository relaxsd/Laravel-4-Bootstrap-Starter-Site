<?php

use Mockery as m;
use Woodling\Woodling;

class UserTest extends TestCase {

    public function testUsername()
    {
        $user = Woodling::retrieve('UserAdmin');
        $this->assertEquals( $user->username, 'admin' );
    }

    public function testGetByUsername()
    {
        $user = Woodling::retrieve('UserAdmin');
        $this->assertNotEquals( $user->getUserByUsername('admin'), false );
    }

    public function testGetByUsernameFail()
    {
        $user = Woodling::retrieve('UserAdmin');
        $this->assertEquals( $user->getUserByUsername('non-user'), false );
    }

}
