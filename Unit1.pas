unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, OleCtrls, SHDocVw, IdHTTP, EncdDecd, DCPcrypt2,
  DCPsha256, IdBaseComponent, IdComponent, IdIOHandler, IdIOHandlerSocket,
  IdSSLOpenSSL;

type
  TForm1 = class(TForm)
    Button1: TButton;
    WebBrowser1: TWebBrowser;
    DCP_sha2561: TDCP_sha256;
    IdSSLIOHandlerSocket1: TIdSSLIOHandlerSocket;
    procedure Button1Click(Sender: TObject);
    procedure WebBrowser1NavigateComplete2(ASender: TObject; const pDisp: IDispatch; var URL: OleVariant);



  private
    function Base64UrlEncode(Text: string): string;
    function GenerateCodeVerifier: string;
    function GenerateCodeChallenge(Verifier: string): string;
    function SHA256Hash(const Text: string): string; // Placeholder function
    function ExtractAuthCode(const URL: string): string;
    function BufferToHex(const Buffer; Size: Integer): string;
    procedure ExchangeCodeForToken(const Code: string);
  public
    { Public declarations }
    CodeVerifier: string;

  end;

var
  Form1: TForm1;
const
    OKTA_AUTH_URL = 'https://alliantdev.oktapreview.com/oauth2/aus1t0j6uo5ePHlhN0h8/v1/authorize';
    CLIENT_ID = '0oa1t0j6krhgXG5Ka0h8';
    REDIRECT_URI = 'http://localhost:8080/login/callback';
    SCOPE = 'openid email profile';
    STATE = 'random-state-string';
implementation

{$R *.dfm}

procedure TForm1.Button1Click(Sender: TObject);
var
   CodeChallenge, AuthURL: string;
begin
  // Generate PKCE Code Verifier and Challenge
  CodeVerifier := GenerateCodeVerifier;
  CodeChallenge := GenerateCodeChallenge(CodeVerifier);

  // Construct Authorization URL
  AuthURL := OKTA_AUTH_URL + '?client_id=' + CLIENT_ID +
             '&redirect_uri=' + REDIRECT_URI +
             '&response_type=code' +
             '&scope=' + SCOPE +
             '&state=' + STATE +
             '&code_challenge_method=S256' +
             '&code_challenge=' + CodeChallenge;

  // Navigate to Authorization URL
  WebBrowser1.Navigate(AuthURL);
end;

procedure TForm1.ExchangeCodeForToken(const Code: string);
const
  TOKEN_ENDPOINT = 'https://alliantdev.oktapreview.com/oauth2/aus1t0j6uo5ePHlhN0h8/v1/token';
var
  HTTP: TIdHTTP;
  SSLHandler: TIdSSLIOHandlerSocket;
  Params: TStringList;
  ResponseText: string;
begin
  HTTP := TIdHTTP.Create(nil);
  SSLHandler := TIdSSLIOHandlerSocket.Create(HTTP);
  Params := TStringList.Create;
  try
     SSLHandler.SSLOptions.Method := sslvSSLv3; // Use the appropriate version
    SSLHandler.SSLOptions.Mode := sslmClient;
    HTTP.IOHandler := SSLHandler;
    Params.Add('grant_type=authorization_code');
    Params.Add('code=' + Code);
    Params.Add('redirect_uri=' + REDIRECT_URI);
    Params.Add('client_id=' + CLIENT_ID);
    Params.Add('code_verifier=' + CodeVerifier);

    try
      ResponseText := HTTP.Post(TOKEN_ENDPOINT, Params);
      // Handle the response here
    except
  on E: Exception do
  begin
    // Show the error message in a dialog
    MessageDlg('Error: ' + E.ClassName + ' - ' + E.Message, mtError, [mbOK], 0);
  end;

    end;

    // Handle the response here
    // Extract the access token from ResponseText
    // You might need to parse the response if it's in JSON format or similar
  finally
    HTTP.Free;
    Params.Free;
  end;
end;

procedure TForm1.WebBrowser1NavigateComplete2(ASender: TObject; const pDisp: IDispatch; var URL: OleVariant);
var
  AuthCode: string;
begin
  if Pos(REDIRECT_URI, URL) = 1 then // Check if URL starts with REDIRECT_URI
  begin
    AuthCode := ExtractAuthCode(URL);
    if AuthCode <> '' then
      ExchangeCodeForToken(AuthCode);
  end;
end;

function TForm1.ExtractAuthCode(const URL: string): string;
var
  QueryString, Param: string;
  URLParts: TStringList;
  i: Integer;
begin
  Result := '';

  // Extract the query string from the URL
  QueryString := Copy(URL, Pos('?', URL) + 1, MaxInt);

  URLParts := TStringList.Create;
  try
    URLParts.Delimiter := '&';
    URLParts.DelimitedText := QueryString;

    for i := 0 to URLParts.Count - 1 do
    begin
      Param := URLParts[i];
      if Pos('code=', Param) = 1 then
      begin
        Result := Copy(Param, Length('code=') + 1, MaxInt);
        Break;
      end;
    end;
  finally
    URLParts.Free;
  end;
end;


function TForm1.Base64UrlEncode(Text: string): string;
var
  Encoded: string;
begin
  Encoded := EncodeString(Text);
  Encoded := StringReplace(Encoded, '+', '-', [rfReplaceAll]);
  Encoded := StringReplace(Encoded, '/', '_', [rfReplaceAll]);
  Encoded := StringReplace(Encoded, '=', '', [rfReplaceAll]); // Remove padding
  Result := Encoded;
end;

function TForm1.GenerateCodeVerifier: string;
const
  CharSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
var
  i: Integer;
begin
  Randomize;
  Result := '';
  for i := 1 to 43 do // Generating 43 characters long string
    Result := Result + CharSet[Random(Length(CharSet)) + 1];
end;

function TForm1.GenerateCodeChallenge(Verifier: string): string;
begin
  Result := Base64UrlEncode(SHA256Hash(Verifier));
end;

function TForm1.SHA256Hash(const Text: string): string;
var
  Digest: array[0..31] of Byte; // SHA-256 produces a 32-byte (256-bit) hash
begin
  DCP_sha2561.Init;  // Initialize the hash
  DCP_sha2561.UpdateStr(Text);  // Update the hash with the input string
  DCP_sha2561.Final(Digest);  // Finalize the hash calculation

  // Convert the hash from a byte array to a hexadecimal string
  Result := BufferToHex(Digest, SizeOf(Digest));
end;
function TForm1.BufferToHex(const Buffer; Size: Integer): string;
const
  HexSymbols = '0123456789ABCDEF';
var
  P: PByte;
  i: Integer;
begin
  SetLength(Result, Size * 2);
  P := @Buffer;
  for i := 0 to Size - 1 do
  begin
    Result[(i * 2) + 1] := HexSymbols[(P^ shr 4) + 1];
    Result[(i * 2) + 2] := HexSymbols[(P^ and $0F) + 1];
    Inc(P);
  end;
end;
end.










