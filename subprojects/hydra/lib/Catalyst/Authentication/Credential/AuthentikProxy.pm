package Catalyst::Authentication::Credential::AuthentikProxy;
use Moose;
use namespace::autoclean;

with 'MooseX::Emulate::Class::Accessor::Fast';

use Try::Tiny qw/ try catch /;

__PACKAGE__->mk_accessors(
    qw/realm username_field/);

sub new {
    my ( $class, $config, $app, $realm ) = @_;

    my $self = { };
    bless $self, $class;

    $self->realm($realm);
    $self->username_field($config->{username_field} || 'username');
    return $self;
}

sub authenticate {
    my ( $self, $c, $realm, $authinfo ) = @_;

    my $remuser = $c->request->headers->header('X-authentik-username');
    return undef unless defined($remuser);
    return undef if ($remuser eq "");

    # $authinfo hash can contain item username (it is optional) - if it is so
    # this username has to be equal to remote_user
    my $authuser = $authinfo->{username};
    return undef if (defined($authuser) && ($authuser ne $remuser));

    $authinfo->{ $self->username_field } = $remuser;
    my $user_obj = $realm->find_user( $authinfo, $c );
    return ref($user_obj) ? $user_obj : undef;
}

1;

__END__
