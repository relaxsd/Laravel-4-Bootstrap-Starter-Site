<?php

class UsersControllerTest extends BaseControllerTestCase {

    public function testShouldLogin()
    {
        $this->requestAction('GET', 'UsersController@getLogin');
        $this->assertRequestOk();
    }

    public function testShouldDoLogin()
    {
        $credentials = array(
            'email'=>'admin@example.org',
            'password'=>'admin',
            'csrf_token' => Session::getToken()
        );

        $this->withInput( $credentials )
            ->requestAction('POST', 'UsersController@postLogin');

        $this->assertRedirection( URL::action('BlogController@getIndex') );
    }

    public function testShouldNotDoLoginWhenWrong()
    {
        $credentials = array(
            'email'=>'someone@somewhere.com',
            'password'=>'wrong',
            'csrf_token' => Session::getToken());

        $this->withInput( $credentials )
            ->requestAction('POST', 'UsersController@postLogin');

        $this->assertRedirection( URL::action('UsersController@getLogin') );
    }

    /**
     * @expectedException  \Illuminate\Session\TokenMismatchException
     */
    public function testShouldNotDoLoginWhenTokenWrong()
    {
        $credentials = array(
            'email'=>'admin@example.org',
            'password'=>'admin',
            'csrf_token' => ''
        );

        $this->withInput( $credentials )
            ->requestAction('POST', 'UsersController@postLogin');
    }

    /**
     * Testing redirect with logged in user.
     */
    public function testLoginShouldRedirectUser()
    {
        $credentials = array(
            'email'=>'admin@example.org',
            'password'=>'admin',
            'csrf_token' => Session::getToken()
        );

        $this->withInput( $credentials )
            ->requestAction('POST', 'UsersController@postLogin');

        $this->requestAction('GET', 'UsersController@getLogin');

        $this->assertRedirection( URL::to('/') );
    }

}
