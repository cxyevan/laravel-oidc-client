<?php

/** @noinspection ContractViolationInspection */

namespace Maicol07\OIDCClient\Auth;

use AssertionError;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Maicol07\OIDCClient\Models\User;
use Maicol07\OpenIDConnect\UserInfo;

class OIDCUserProvider implements UserProvider
{
    // 通过Userinfo_endpoint返回的userinfo对象，来查询本地数据库的user
    final public function retrieveByInfo(UserInfo $user_info): User
    {
        $attrs = $user_info->attrs();
        $uuid = $attrs->pull('sub');

        $user = config('auth.providers.users.model')::where('uuid', $uuid)->firstOrNew();
        try {
            assert($user instanceof User);
        } catch (AssertionError) {
            throw new AssertionError('User model must extend ' . User::class);
        }

        /** @noinspection UnusedFunctionResultInspection */
        $attrs->each(fn (mixed $value, string $attr) => $user->$attr = $value);

        return $user;
    }

    // 通过claim信息构建的userinfo对象，来查询本地数据库的user
    final public function retrieveByClaimInfo(UserInfo $user_info): User
    {
        $attrs = $user_info->attrs();

        $unique_name = $attrs->get('unique_name');

        $user = config('auth.providers.users.model')::where('unique_name', $unique_name)->first();
        if (!$user) {
            throw new AssertionError('User with NT account "' . $unique_name . '" was not registered in application!');
        }
        try {
            assert($user instanceof User);
        } catch (AssertionError) {
            throw new AssertionError('User model must extend ' . User::class);
        }

        /** @noinspection UnusedFunctionResultInspection */
        $attrs->each(fn (mixed $value, string $attr) => $user->$attr = $value);

        return $user;
    }

    final public function retrieveById(mixed $identifier): ?User
    {
        return null;
    }

    final public function retrieveByToken(mixed $identifier, mixed $token): ?User
    {
        return null;
    }

    final public function updateRememberToken(Authenticatable|User $user, mixed $token): void
    {
    }

    final public function retrieveByCredentials(array $credentials): ?User
    {
        return null;
    }

    final public function validateCredentials(Authenticatable $user, array $credentials): bool
    {
        return true;
    }
}
