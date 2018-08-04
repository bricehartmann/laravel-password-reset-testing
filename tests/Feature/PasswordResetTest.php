<?php

namespace Tests\Feature;

use App\User;
use Hash;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Foundation\Testing\WithFaker;
use Notification;
use Password;
use Tests\TestCase;

class PasswordResetTest extends TestCase
{
    use WithFaker;

    const ROUTE_PASSWORD_EMAIL = 'password.email';
    const ROUTE_PASSWORD_REQUEST = 'password.request';
    const ROUTE_PASSWORD_RESET = 'password.reset';
    const ROUTE_PASSWORD_RESET_SUBMIT = 'password.reset.submit';

    const USER_ORIGINAL_PASSWORD = 'secret';

    /**
     * Testing showing the password reset request page.
     */
    public function testShowPasswordResetRequestPage()
    {
        $this
            ->get(route(self::ROUTE_PASSWORD_REQUEST))
            ->assertSuccessful()
            ->assertSee('Reset Password')
            ->assertSee('E-Mail Address')
            ->assertSee('Send Password Reset Link');
    }

    /**
     * Testing submitting the password reset request with an invalid
     * email address.
     */
    public function testSubmitPasswordResetRequestInvalidEmail()
    {
        $this
            ->followingRedirects()
            ->from(route(self::ROUTE_PASSWORD_REQUEST))
            ->post(route(self::ROUTE_PASSWORD_EMAIL), [
                'email' => str_random(),
            ])
            ->assertSuccessful()
            ->assertSee(__('validation.email', [
                'attribute' => 'email'
            ]));
    }

    /**
     * Testing submitting the password reset request with an email
     * address not in the database.
     */
    public function testSubmitPasswordResetRequestEmailNotFound()
    {
        $this
            ->followingRedirects()
            ->from(route(self::ROUTE_PASSWORD_REQUEST))
            ->post(route(self::ROUTE_PASSWORD_EMAIL), [
                'email' => $this->faker->unique()->safeEmail,
            ])
            ->assertSuccessful()
            ->assertSee(e(__('passwords.user')));
    }

    /**
     * Testing submitting a password reset request.
     */
    public function testSubmitPasswordResetRequest()
    {
        $user = factory(User::class)->create();

        $this
            ->followingRedirects()
            ->from(route(self::ROUTE_PASSWORD_REQUEST))
            ->post(route(self::ROUTE_PASSWORD_EMAIL), [
                'email' => $user->email,
            ])
            ->assertSuccessful()
            ->assertSee(__('passwords.sent'));

        Notification::assertSentTo($user, ResetPassword::class);
    }
}
