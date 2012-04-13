package Net::OAuth2::Profile::Password;
use warnings;
use strict;
use base qw(Net::OAuth2::Profile::Base);
use JSON;
use URI;
use Net::OAuth2::AccessToken;
use HTTP::Request::Common;

__PACKAGE__->mk_accessors(qw/redirect_uri grant_type/);

sub authorize_params {
	my $self = shift;
	my %options = $self->SUPER::authorize_params(@_);
	$options{response_type} = 'code';
	$options{redirect_uri} = $self->redirect_uri if defined $self->redirect_uri;

	return %options;
}

sub get_access_token {
	my $self = shift;
	my %prm  = @_;
	my $dta  = {};
	
	my $request;
	if ($self->client->access_token_method eq 'POST') {
		$request = POST($self->client->access_token_url(), {$self->access_token_params( %prm)});
	} else {
		$request = HTTP::Request->new(
			$self->client->access_token_method => $self->client->access_token_url(
				$self->access_token_params( %prm)
			)
		);
	}
	my $response = $self->client->request($request);

	die "Fetch of access token failed: " . $response->status_line . ": " . $response->decoded_content
		unless $response->is_success;
	$dta = _parse_json($response->decoded_content);
	$dta = _parse_query_string($response->decoded_content) unless defined $dta;
	die "Unable to parse access token response '".substr($response->decoded_content, 0, 64)."'" unless defined $dta;

	$dta->{client} = $self->client;
	return Net::OAuth2::AccessToken->new(%$dta);
}

sub access_token_params {
	my $self = shift;

	my %options = $self->SUPER::access_token_params(undef, @_);
	$options{grant_type} = 'password';
	return %options;
}

sub _parse_query_string {
	my $str = shift;
	my $uri = URI->new;
	$uri->query($str);
	return {$uri->query_form};
}

sub _parse_json {
	my $str = shift;
	my $obj = eval{local $SIG{__DIE__}; decode_json($str)};
	return $obj;
}

=head1 NAME

Net::OAuth2::Profile::Password - OAuth Password Profile

=head1 SYNOPSIS

	my $client = Net::OAuth2::Client->new( 
		$client_id,
		$client_secret,
		%options
		)->password();
	    
	my $token = $client->get_access_token( 
		username => 'myname',
		password => 'secret',
		);

	$token->get('/service/v1.0/data/');

=head1 SEE ALSO

L<Net::OAuth>

=head1 LICENSE AND COPYRIGHT

Copyright 2012 Carl Vincent, based on work by Kieth Grennan

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut


1;
