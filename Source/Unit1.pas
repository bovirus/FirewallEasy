unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, ComObj, ShellAPI, ComCtrls, ExtCtrls, Menus, Registry,
  IniFiles;

type
  TMain = class(TForm)
    AddBtn: TButton;
    RemBtn: TButton;
    CheckBtn: TButton;
    FirewallBtn: TButton;
    CloseBtn2: TButton;
    OpenDialog: TOpenDialog;
    SearchEdt: TEdit;
    StatusBar: TStatusBar;
    ImportDialog: TOpenDialog;
    ExportDialog: TSaveDialog;
    MainMenu1: TMainMenu;
    FileBtn: TMenuItem;
    ImportBtn: TMenuItem;
    ExportBtn: TMenuItem;
    HelpBtn: TMenuItem;
    AboutBtn: TMenuItem;
    ListView: TListView;
    PopupMenu: TPopupMenu;
    RemBtn2: TMenuItem;
    N1: TMenuItem;
    SettingsBtn: TMenuItem;
    N2: TMenuItem;
    CloseBtn: TMenuItem;
    N3: TMenuItem;
    CMDOptions: TMenuItem;
    DonateBtn: TMenuItem;
    N4: TMenuItem;
    procedure AddBtnClick(Sender: TObject);
    procedure RemBtnClick(Sender: TObject);
    procedure FirewallBtnClick(Sender: TObject);
    procedure CloseBtn2Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure CheckBtnClick(Sender: TObject);
    procedure SearchEdtMouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: integer);
    procedure SearchEdtChange(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure SearchEdtKeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure FormKeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure SearchEdtKeyUp(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure ImportBtnClick(Sender: TObject);
    procedure ExportBtnClick(Sender: TObject);
    procedure AboutBtnClick(Sender: TObject);
    procedure ListViewMouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: integer);
    procedure ListViewKeyUp(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure ListViewDblClick(Sender: TObject);
    procedure ListViewKeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure RemBtn2Click(Sender: TObject);
    procedure CloseBtnClick(Sender: TObject);
    procedure SettingsBtnClick(Sender: TObject);
    procedure CMDOptionsClick(Sender: TObject);
    procedure DonateBtnClick(Sender: TObject);
  protected
    procedure WMDropFiles (var Msg: TMessage); message WM_DropFiles;
    procedure Status(const Content: string = '');
  private
    procedure LoadRegRules;
    procedure WMCopyData(var Msg: TWMCopyData); message WM_COPYDATA;
    function HandleParams: string;
    procedure SyncAppInfo;
    procedure FileAssociation(const Recreate: boolean);
    procedure FileExtension(const Recreate: boolean);
    { Private declarations }
  public
    CompactContextMenu, AddedControlPanel: boolean;
    procedure ImportRules(const FilePath: string);
    procedure ExportRules(const FilePath: string);
    procedure ContextMenu(const Recreate, CompactMode: boolean);
    procedure AddClassIdentifier;
    procedure RemoveClassIdentifier;
    procedure AddControlPanelEntry;
    procedure RemoveControlPanelEntry;
    { Public declarations }
  end;

var
  Main: TMain;
  RuleNames, RulePaths: TStringList;
  CloseApplication: boolean;
  BlockedCount, UnblockedCount: integer;
  SystemLang: string;

  // Tranlate / Перевод
  IDS_SEARCH: string;

  IDS_ABOUT, IDS_LAST_UPDATE: string;

  IDS_RULE_SUCCESSFULLY_CREATED, IDS_RULE_ALREADY_EXISTS, IDS_RULE_SUCCESSFULLY_REMOVED, IDS_RULE_NOT_FOUND, IDS_APP_NOT_FOUND, IDS_CHOOSE_RULE,
  IDS_RULES_SUCCESSFULLY_CREATED, IDS_FAILED_CREATE_RULES, IDS_RULES_SUCCESSFULLY_REMOVED, IDS_FAILED_REMOVE_RULES, IDS_REMOVED_RULES_FOR_NONEXISTENT_APPS,
  IDS_INFO, IDS_RULES_FOR_NONEXISTENT_APPS_NOT_FOUND, IDS_RULES_SUCCESSFULLY_IMPORTED, IDS_RULES_SUCCESSFULLY_EXPORTED, IDS_CONTEXT_MENU, IDS_BLOCK_ACCESS,
  IDS_UNBLOCK_ACCESS, IDS_UNBLOCK_ACCESS_CONTEXT_MENU, IDS_ADD_TO_CONTROL_PANEL, IDS_APPLY, IDS_CANCEL, IDS_COMMAND_LINE_OPTIONS, IDS_COMMAND_LINE_OPTIONS_TEXT: string;

const
  AppName = 'Firewall Easy';
  AppID = 'FirewallEasy';
  AppUUID = '{4BBF9C81-ABF8-4BA9-A5FC-F654B754F30F}'; // Classic Control Panel
  AppVersion = '0.9';
  AppUpdateDate = '27.03.26';

  NET_FW_IP_PROTOCOL_TCP = 6;
  NET_FW_IP_PROTOCOL_UDP = 17;

  NET_FW_RULE_DIR_IN = 1;   // IN  - incoming connections / входящие соединения
  NET_FW_RULE_DIR_OUT = 2;  // OUT - outgoing / исходящие

  KEY_WOW64_64KEY = $0100;

implementation

uses Unit2;

{$R *.dfm}
{$R Icons.res}
{$R UAC.res}

function GetUserDefaultUILanguage: LANGID; stdcall; external 'kernel32.dll';

function ChangeWindowMessageFilterEx(hWnd: HWND; msg: UINT; 
  action: DWORD; pChangeFilterStruct: Pointer): BOOL; 
  stdcall; external 'user32.dll';
const
  MSGFLT_ALLOW = 1;

function CutStr(Str: string; CharCount: integer): string;
begin
  if Length(Str) > CharCount then
    Result:=Copy(Str, 1, CharCount - 3) + '...'
  else
    Result:=Str;
end;

procedure AddRuleToFirewall(const Caption, Executable: string; NET_FW_IP_PROTOCOL, NET_FW_RULE_DIR: integer);
const
  NET_FW_PROFILE2_DOMAIN = 1;
  NET_FW_PROFILE2_PRIVATE = 2;
  NET_FW_PROFILE2_PUBLIC = 4;

  NET_FW_IP_PROTOCOL_ICMPv4 = 1;
  NET_FW_IP_PROTOCOL_ICMPv6 = 58;

  NET_FW_ACTION_ALLOW = 1;
  NET_FW_ACTION_BLOCK = 0;
var
  fwPolicy2: OleVariant;
  RulesObject: OleVariant;
  Profile: integer;
  NewRule: OleVariant;
begin
  Profile:=NET_FW_PROFILE2_PRIVATE or NET_FW_PROFILE2_PUBLIC or NET_FW_PROFILE2_DOMAIN; // Профили
  fwPolicy2:=CreateOleObject('HNetCfg.FwPolicy2');
  RulesObject:=fwPolicy2.Rules;
  NewRule:=CreateOleObject('HNetCfg.FWRule');
  NewRule.Name:=Caption;
  NewRule.Description:=Caption;
  NewRule.Applicationname:=Executable;
  NewRule.Protocol:=NET_FW_IP_PROTOCOL; // Протоколы
  NewRule.Direction:=NET_FW_RULE_DIR; // incoming connections, outgoing / Входящие и исходящие соединения
  NewRule.Enabled:=true;
  NewRule.Grouping:=AppID;
  NewRule.Profiles:=Profile;
  NewRule.Action:=NET_FW_ACTION_BLOCK; // NET_FW_ACTION_BLOCK - запретить, NET_FW_ACTION_ALLOW - разрешить
  RulesObject.Add(NewRule);
end;

// Просто пример, вероятно смысла нет, потому что диалоги добавления будут не проще, чем в брандмауэер
// Just an example, probably no point, because the add dialogs will be no simpler than in the firewall
// AddBlockPortRule('"TestPort"', 5791, NET_FW_IP_PROTOCOL_UDP, NET_FW_RULE_DIR_IN);
{procedure AddBlockPortRule(const Caption: string; const Port: integer; NET_FW_IP_PROTOCOL, NET_FW_RULE_DIR: integer);
const
  NET_FW_PROFILE2_DOMAIN = 1;
  NET_FW_PROFILE2_PRIVATE = 2;
  NET_FW_PROFILE2_PUBLIC = 4;

  NET_FW_IP_PROTOCOL_TCP = 6;

  NET_FW_ACTION_BLOCK = 0;
var
  fwPolicy2: OleVariant;
  RulesObject: OleVariant;
  NewRule: OleVariant;
  Profile: integer;
begin
  Profile:=NET_FW_PROFILE2_DOMAIN or NET_FW_PROFILE2_PRIVATE or NET_FW_PROFILE2_PUBLIC;
  fwPolicy2:=CreateOleObject('HNetCfg.FwPolicy2');
  RulesObject:=fwPolicy2.Rules;
  NewRule:=CreateOleObject('HNetCfg.FWRule');
  NewRule.Name:=Caption;
  NewRule.Description:=Caption; // + Port?
  NewRule.Protocol:=NET_FW_IP_PROTOCOL;
  NewRule.LocalPorts:=Port;
  NewRule.Direction:=NET_FW_RULE_DIR;
  NewRule.Enabled:=true;
  NewRule.Profiles:=Profile;
  NewRule.Action:=NET_FW_ACTION_BLOCK;
  RulesObject.Add(NewRule);
end;}

procedure AddRulesForApp(const FilePath: string);
var
  RuleCaption: string;
begin
  RuleCaption:=ExtractFileName(FilePath) + ' ' + DateToStr(Date) + ' ' + TimeToStr(Time);

  // Add all rules to Firewall / Добавляем все правила в Firewall
  AddRuleToFirewall(RuleCaption + '_TCP_IN', FilePath, NET_FW_IP_PROTOCOL_TCP, NET_FW_RULE_DIR_IN);
  AddRuleToFirewall(RuleCaption + '_TCP_OUT', FilePath, NET_FW_IP_PROTOCOL_TCP, NET_FW_RULE_DIR_OUT);
  AddRuleToFirewall(RuleCaption + '_UDP_IN', FilePath, NET_FW_IP_PROTOCOL_UDP, NET_FW_RULE_DIR_IN);
  AddRuleToFirewall(RuleCaption + '_UDP_OUT', FilePath, NET_FW_IP_PROTOCOL_UDP, NET_FW_RULE_DIR_OUT);

  // Update the list, update RuleNames, RulePaths / Обновляем список, обновляем RuleNames, RulePaths
  Main.LoadRegRules;
end;

procedure RemoveRuleFromFirewall(const RuleName: string);
const
  NET_FW_PROFILE2_DOMAIN = 1;
  NET_FW_PROFILE2_PRIVATE = 2;
  NET_FW_PROFILE2_PUBLIC = 4;
var
  Profile: integer;
  Policy2: OleVariant;
  RObject: OleVariant;
begin
  Profile:=NET_FW_PROFILE2_PRIVATE or NET_FW_PROFILE2_PUBLIC or NET_FW_PROFILE2_DOMAIN;
  Policy2:=CreateOleObject('HNetCfg.FwPolicy2');
  RObject:=Policy2.Rules;
  RObject.Remove(RuleName);
end;

procedure RemoveAppRules(const RuleName: string);
begin
  RemoveRuleFromFirewall(RuleName + '_TCP_IN');
  RemoveRuleFromFirewall(RuleName + '_TCP_OUT');
  RemoveRuleFromFirewall(RuleName + '_UDP_IN');
  RemoveRuleFromFirewall(RuleName + '_UDP_OUT');

  // Update the list, update RuleNames, RulePaths / Обновляем список, обновляем RuleNames, RulePaths
  Main.LoadRegRules;
end;

procedure SendMessageToHandle(TrgWND: HWND; MsgToHandle: string);
var
  CDS: TCopyDataStruct;
begin
  CDS.dwData:=0;
  CDS.cbData:=(Length(MsgToHandle) + 1) * Sizeof(char);
  CDS.lpData:=PChar(MsgToHandle);
  SendMessage(TrgWND, WM_COPYDATA, Integer(Application.Handle), Integer(@CDS));
end;

function GetLocaleInformation(Flag: integer): string; // If there are multiple languages in the system (with sorting) / Если в системе несколько языков (с сортировкой)
var
  pcLCA: array [0..63] of Char;
begin
  if GetLocaleInfo((DWORD(SORT_DEFAULT) shl 16) or Word(GetUserDefaultUILanguage), Flag, pcLCA, Length(pcLCA)) <= 0 then
    pcLCA[0]:=#0;
  Result:=pcLCA;
end;

{function GetLocaleInformation2(Flag: integer): string; // Legacy
var
  pcLCA: array [0..20] of Char;
begin
  if GetLocaleInfo(LOCALE_SYSTEM_DEFAULT, Flag, pcLCA, Length(pcLCA)) <= 0 then
    pcLCA[0]:=#0;
  Result:=pcLCA;
end;}

procedure TMain.AddBtnClick(Sender: TObject);
begin
  if not OpenDialog.Execute then Exit;
  if Pos(OpenDialog.FileName, RulePaths.Text) = 0 then begin
    AddRulesForApp(OpenDialog.FileName);
    Status(Format(IDS_RULE_SUCCESSFULLY_CREATED, [CutStr(ExtractFileName(OpenDialog.FileName), 22)]));
  end else
    Status(Format(IDS_RULE_ALREADY_EXISTS, [CutStr(ExtractFileName(OpenDialog.FileName), 23)]));
end;

procedure TMain.RemBtnClick(Sender: TObject);
begin
  if ListView.ItemIndex <> - 1 then begin
    Status(Format(IDS_RULE_SUCCESSFULLY_REMOVED, [CutStr(ExtractFileName(RulePaths.Strings[ListView.ItemIndex]), 22)])); // После удаления названия уже не будет, поэтому перед удалением
    RemoveAppRules(RuleNames.Strings[ListView.ItemIndex]);
  end else
    Status(IDS_CHOOSE_RULE);
end;

procedure TMain.FirewallBtnClick(Sender: TObject);
begin
  ShellExecute(0, 'open', 'WF.msc', nil, nil, SW_SHOWNORMAL);
end;

procedure TMain.CloseBtn2Click(Sender: TObject);
begin
  Close;
end;

procedure TMain.WMDropFiles(var Msg: TMessage);
var
  i, AmountFiles, Size: integer;
  FileName: PChar; FilePath: string;
begin
  inherited;
  AmountFiles:=DragQueryFile(Msg.WParam, $FFFFFFFF, FileName, 255);
  BlockedCount:=0;
  for i:=0 to AmountFiles - 1 do begin
    Size:=DragQueryFile(Msg.WParam, i, nil, 0) + 1;
    FileName:=StrAlloc(Size);
    DragQueryFile(Msg.WParam, i, FileName, Size);
    FilePath:=StrPas(FileName);
    StrDispose(FileName);
    if (AnsiLowerCase(ExtractFileExt(FilePath)) = '.exe') and
       (FileExists(FilePath)) and (Pos(FilePath, RulePaths.Text) = 0) then
    begin
      AddRulesForApp(FilePath);
      Inc(BlockedCount);
    end;
  end;
  DragFinish(Msg.WParam);
  
  if BlockedCount > 0 then
    Status(IDS_RULES_SUCCESSFULLY_CREATED + ' ' + IntToStr(BlockedCount))
  else
    Status(IDS_FAILED_CREATE_RULES);
end;

procedure TMain.LoadRegRules;
var
  Rules: TStringList;
  i: integer;
  Reg: TRegistry;
  SubKeyNames: TStringList;
  RegName: string;
  Item: TListItem;
begin
  RuleNames.Clear;
  RulePaths.Clear;
  ListView.Clear;

  Rules:=TStringList.Create;
  Reg:=TRegistry.Create;
  SubKeyNames:=TStringList.Create;
  Reg.RootKey:=HKEY_LOCAL_MACHINE;
  Reg.OpenKeyReadOnly('SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\FirewallRules');
  Reg.GetValueNames(Rules);
  for i:=0 to Rules.Count - 1 do begin
    RegName:=Reg.ReadString(Rules.Strings[i]);
    if (Pos('EmbedCtxt=' + AppID, RegName) > 0) and (Pos('Dir=In', RegName) > 0) and (Pos('_UDP_', RegName) > 0) then begin
      Delete(RegName, 1, Pos('App=', RegName) + 3);
      RulePaths.Add(Copy(RegName, 1, Pos('|', RegName) - 1));
      Delete(RegName, 1, Pos('Name=', RegName) + 4);
      RegName:=Copy(RegName, 1, Pos('|', RegName) - 1);
      RegName:=Copy(RegName, 1, Pos('_UDP_', RegName) - 1);
      RuleNames.Add(RegName);
      Item:=Main.ListView.Items.Add;
      Item.Caption:=ExtractFileName(RulePaths.Strings[RulePaths.Count - 1]);
      Item.SubItems.Add(RulePaths.Strings[RulePaths.Count - 1]);
    end;
  end;
  Reg.CloseKey;
  Rules.Free;
  Reg.Free;
end;

procedure TMain.Status(const Content: string);
begin
  StatusBar.SimpleText:=' ' + Content;
end;

function TMain.HandleParams: string;
var
  Silent: boolean;
  i, BlockParam, UnblockParam, ImportParam, ExportParam: integer;
begin
  if ParamCount < 1 then Exit;

  Silent:=false;
  BlockParam:=0;
  UnblockParam:=0;
  ImportParam:=0;
  ExportParam:=0;

  for i:=1 to ParamCount do begin
    if (AnsiLowerCase(ParamStr(i)) = '-b') or (AnsiLowerCase(ParamStr(i)) = '--block') then
      BlockParam:=i + 1
    else if (AnsiLowerCase(ParamStr(i)) = '-u') or (AnsiLowerCase(ParamStr(i)) = '--unblock') then
      UnblockParam:=i + 1
    else if (AnsiLowerCase(ParamStr(i)) = '-i') or (AnsiLowerCase(ParamStr(i)) = '--import') then
      ImportParam:=i + 1
    else if (AnsiLowerCase(ParamStr(i)) = '-e') or (AnsiLowerCase(ParamStr(i)) = '--export') then
      ExportParam:=i + 1
    else if (AnsiLowerCase(ParamStr(i)) = '-s') or (AnsiLowerCase(ParamStr(i)) = '--silent') then
      Silent:=true;
  end;

  // Block
  if (BlockParam > 0) and (AnsiLowerCase(ExtractFileExt(ParamStr(BlockParam))) = '.exe') then begin
    if FileExists(ExpandFileName(ParamStr(BlockParam))) then begin
      if Pos(AnsiLowerCase(ExpandFileName(ParamStr(BlockParam))), AnsiLowerCase(RulePaths.Text)) = 0 then begin
        AddRulesForApp(ExpandFileName(ParamStr(BlockParam)));
        Status(Format(IDS_RULE_SUCCESSFULLY_CREATED, [CutStr(ExtractFileName(ParamStr(BlockParam)), 22)]));
        Inc(BlockedCount);
        Result:='%ADDED%';
      end else begin
        Status(Format(IDS_RULE_ALREADY_EXISTS, [CutStr(ExtractFileName(ParamStr(BlockParam)), 22)]));
        Result:='%EXISTS%';
      end;
    end else begin
      Status(Format(IDS_APP_NOT_FOUND, [CutStr(ExtractFileName(ParamStr(BlockParam)), 22)]));
      Result:='%ABSENT%';
    end;

  // Unblock
  end else if (UnblockParam > 0) and (AnsiLowerCase(ExtractFileExt(ParamStr(UnblockParam))) = '.exe') then begin
    if Pos(AnsiLowerCase(ExpandFileName(ParamStr(UnblockParam))), AnsiLowerCase(RulePaths.Text)) > 0 then begin
      for i:=0 to RuleNames.Count - 1 do
        if AnsiLowerCase(ExpandFileName(ParamStr(UnblockParam))) = AnsiLowerCase(RulePaths.Strings[i]) then begin
          RemoveAppRules(RuleNames.Strings[i]);
          Status(Format(IDS_RULE_SUCCESSFULLY_REMOVED, [CutStr(ExtractFileName(ParamStr(UnblockParam)), 22)]));
          Inc(UnblockedCount);
          Result:='%REMOVED%';
          Break;
        end;
    end else begin
      Status(Format(IDS_RULE_NOT_FOUND, [CutStr(ExtractFileName(ParamStr(UnblockParam)), 22)]));
      Result:='%MISSING%';
    end;

  // Import
  end else if (ImportParam > 0) and (AnsiLowerCase(ExtractFileExt(ParamStr(ImportParam))) = '.fer') then begin
    ImportRules(ParamStr(ImportParam));
    Result:='%IMPORTED%';

  // Export
  end else if (ExportParam > 0) and (AnsiLowerCase(ExtractFileExt(ParamStr(ExportParam))) = '.fer') then
    ExportRules(ParamStr(ExportParam));

  // Silent
  if Silent then begin
    CloseApplication:=true;
    Result:='';
  end;
end;

procedure TMain.ContextMenu(const Recreate, CompactMode: boolean);
const
  RegKey = '\exefile\shell\' + AppID;
var
  Reg: TRegistry;
  ExePath: string;
begin
  Reg:=TRegistry.Create;
  Reg.RootKey:=HKEY_CLASSES_ROOT;
  if Recreate and Reg.KeyExists(RegKey) then
    Reg.DeleteKey(RegKey);
  if (Reg.OpenKeyReadOnly(RegKey) = false) and Reg.OpenKey(RegKey, true) then begin

    ExePath:=ParamStr(0);
    Reg.WriteString('Icon', ExePath + ',0');
    if CompactMode then begin
      Reg.WriteString('MUIVerb', IDS_BLOCK_ACCESS);
      Reg.OpenKey(RegKey + '\Command', true);
      Reg.WriteString('', '"' + ExePath + '" --block "%1"');
    end else begin
      Reg.WriteString('MUIVerb', IDS_CONTEXT_MENU);
      Reg.WriteString('SubCommands', '');
      Reg.OpenKey(RegKey + '\Shell\Block', true);
      Reg.WriteString('MUIVerb', IDS_BLOCK_ACCESS);
      Reg.WriteString('Icon', ExePath + ',1');
      Reg.OpenKey(RegKey + '\Shell\Block\Command', true);
      Reg.WriteString('', '"' + ExePath + '" --block "%1"');
      Reg.OpenKey(RegKey + '\Shell\Unblock', true);
      Reg.WriteString('MUIVerb', IDS_UNBLOCK_ACCESS);
      Reg.WriteString('Icon', ExePath + ',2');
      Reg.OpenKey(RegKey + '\Shell\Unblock\Command', true);
      Reg.WriteString('', '"' + ExePath + '" --unblock "%1"');
    end;

    Reg.CloseKey;
  end;
  Reg.Free;
end;

procedure TMain.FormCreate(Sender: TObject);
var
  WND: HWND;
  Ini: TIniFile;
  LangFileName, Event: string;
begin
  // Translate / Перевод
  SystemLang:=GetLocaleInformation(LOCALE_SENGLANGUAGE);
  if SystemLang = 'Chinese' then
    SystemLang:='Chinese (Simplified)'
  else if Pos('Spanish', SystemLang) > 0 then
    SystemLang:='Spanish'
  else if Pos('Portuguese', SystemLang) > 0 then
    SystemLang:='Portuguese';

  //SystemLang:='English';
  LangFileName:=SystemLang + '.ini';
  if not FileExists(ExtractFilePath(ParamStr(0)) + 'Languages\' + LangFileName) then begin
    LangFileName:='English.Ini';
    SystemLang:='English';
  end;
  Ini:=TIniFile.Create(ExtractFilePath(ParamStr(0)) + 'Languages\' + LangFileName);

  FileBtn.Caption:=UTF8ToAnsi(Ini.ReadString('Main', 'FILE', 'File'));
  ImportBtn.Caption:=UTF8ToAnsi(Ini.ReadString('Main', 'IMPORT', 'Import'));
  ExportBtn.Caption:=UTF8ToAnsi(Ini.ReadString('Main', 'EXPORT', 'Export'));
  SettingsBtn.Caption:=UTF8ToAnsi(Ini.ReadString('Main', 'SETTINGS', 'Settings'));
  CloseBtn.Caption:=UTF8ToAnsi(Ini.ReadString('Main', 'EXIT', 'Exit'));
  CloseBtn2.Caption:=CloseBtn.Caption;
  HelpBtn.Caption:=UTF8ToAnsi(Ini.ReadString('Main', 'HELP', 'Help'));
  IDS_INFO:=UTF8ToAnsi(Ini.ReadString('Main', 'INFO', 'Application allows you to block internet access to other applications using the Windows Firewall.'));
  DonateBtn.Caption:=UTF8ToAnsi(Ini.ReadString('Main', 'DONATE', 'Donate'));
  IDS_ABOUT:=UTF8ToAnsi(Ini.ReadString('Main', 'ABOUT', 'About...'));
  AboutBtn.Caption:=IDS_ABOUT;

  IDS_COMMAND_LINE_OPTIONS:=UTF8ToAnsi(Ini.ReadString('Main', 'COMMAND_LINE_OPTIONS', 'Command Line Options'));
  CMDOptions.Caption:=IDS_COMMAND_LINE_OPTIONS;
  IDS_COMMAND_LINE_OPTIONS_TEXT:=StringReplace(UTF8ToAnsi(Ini.ReadString('Main', 'COMMAND_LINE_OPTIONS_TEXT', 'Block internet:\n-b "App.exe" or --block "App.exe"\n\nUnblock internet:\n-u "App.exe" or --unblock "App.exe"\n\nImport rules:\n-i "Rules.fer" or --import "Rules.fer"\n\nExport rules:\n-e "Rules.fer" or --export "Rules.fer"\n\nSilent mode:\n-s or --silent')), '\n', sLineBreak, [rfReplaceAll]);

  ListView.Columns[0].Caption:=UTF8ToAnsi(Ini.ReadString('Main', 'APP_NAME', 'Name'));
  ListView.Columns[1].Caption:=UTF8ToAnsi(Ini.ReadString('Main', 'APP_PATH', 'Path'));

  IDS_SEARCH:=UTF8ToAnsi(Ini.ReadString('Main', 'SEARCH', 'Search...'));
  SearchEdt.Text:=IDS_SEARCH;

  AddBtn.Caption:=UTF8ToAnsi(Ini.ReadString('Main', 'ADD', 'Add'));
  OpenDialog.Filter:=UTF8ToAnsi(Ini.ReadString('Main', 'ADD_FILTER_NAME', 'Applications')) + OpenDialog.Filter;
  RemBtn.Caption:=UTF8ToAnsi(Ini.ReadString('Main', 'REMOVE', 'Remove'));
  RemBtn2.Caption:=RemBtn.Caption;
  CheckBtn.Caption:=UTF8ToAnsi(Ini.ReadString('Main', 'CHECK', 'Check'));
  FirewallBtn.Caption:=UTF8ToAnsi(Ini.ReadString('Main', 'FIREWALL', 'Firewall'));

  IDS_RULES_SUCCESSFULLY_IMPORTED:=UTF8ToAnsi(Ini.ReadString('Main', 'RULES_SUCCESSFULLY_IMPORTED', 'Rules successfully imported'));
  IDS_RULES_SUCCESSFULLY_EXPORTED:=UTF8ToAnsi(Ini.ReadString('Main', 'RULES_SUCCESSFULLY_EXPORTED', 'Rules successfully exported'));
  IDS_RULE_SUCCESSFULLY_CREATED:=UTF8ToAnsi(Ini.ReadString('Main', 'RULE_SUCCESSFULLY_CREATED', 'Rule for application "%s" successfully created'));
  IDS_RULE_ALREADY_EXISTS:=UTF8ToAnsi(Ini.ReadString('Main', 'RULE_ALREADY_EXISTS', 'Rule for app "%s" already exists'));
  IDS_RULE_SUCCESSFULLY_REMOVED:=UTF8ToAnsi(Ini.ReadString('Main', 'RULE_SUCCESSFULLY_REMOVED', 'Rule for application "%s" successfully removed'));
  IDS_RULE_NOT_FOUND:=UTF8ToAnsi(Ini.ReadString('Main', 'RULE_NOT_FOUND', 'Rule for app "%s" doesn''t exist'));
  IDS_APP_NOT_FOUND:=UTF8ToAnsi(Ini.ReadString('Main', 'APP_NOT_FOUND', 'Application "%s" doesn''t exist'));
  IDS_CHOOSE_RULE:=UTF8ToAnsi(Ini.ReadString('Main', 'CHOOSE_RULE', 'Choose rule'));
  IDS_RULES_SUCCESSFULLY_CREATED:=UTF8ToAnsi(Ini.ReadString('Main', 'RULES_SUCCESSFULLY_CREATED', 'Rules successfully created:'));
  IDS_FAILED_CREATE_RULES:=UTF8ToAnsi(Ini.ReadString('Main', 'FAILED_CREATE_RULES', 'Failed to create rules'));
  IDS_RULES_SUCCESSFULLY_REMOVED:=UTF8ToAnsi(Ini.ReadString('Main', 'RULES_SUCCESSFULLY_REMOVED', 'Rules successfully removed:'));
  IDS_FAILED_REMOVE_RULES:=UTF8ToAnsi(Ini.ReadString('Main', 'FAILED_REMOVE_RULES', 'Failed to remove rules'));
  IDS_REMOVED_RULES_FOR_NONEXISTENT_APPS:=UTF8ToAnsi(Ini.ReadString('Main', 'REMOVED_RULES_FOR_NONEXISTENT_APPS', 'Removed rules for nonexistent applications:'));
  IDS_RULES_FOR_NONEXISTENT_APPS_NOT_FOUND:=UTF8ToAnsi(Ini.ReadString('Main', 'RULES_FOR_NONEXISTENT_APPS_NOT_FOUND', 'Rules for nonexistent applications not found'));

  IDS_LAST_UPDATE:=UTF8ToAnsi(Ini.ReadString('Main', 'LAST_UPDATE', 'Last update:'));
  IDS_CONTEXT_MENU:=UTF8ToAnsi(Ini.ReadString('Main', 'CONTEXT_MENU', 'Firewall rules'));
  IDS_BLOCK_ACCESS:=UTF8ToAnsi(Ini.ReadString('Main', 'BLOCK_ACCESS', 'Block internet access'));
  IDS_UNBLOCK_ACCESS:=UTF8ToAnsi(Ini.ReadString('Main', 'UNBLOCK_ACCESS', 'Unblock internet access'));
  IDS_ADD_TO_CONTROL_PANEL:=UTF8ToAnsi(Ini.ReadString('Main', 'ADD_TO_CONTROL_PANEL', 'Add to Control Panel'));

  IDS_UNBLOCK_ACCESS_CONTEXT_MENU:=UTF8ToAnsi(Ini.ReadString('Main', 'UNBLOCK_ACCESS_CONTEXT_MENU', 'Unblock internet access in context menu'));
  IDS_APPLY:=UTF8ToAnsi(Ini.ReadString('Main', 'APPLY', 'Apply'));
  IDS_CANCEL:=UTF8ToAnsi(Ini.ReadString('Main', 'CANCEL', 'Cancel'));

  Ini.Free;

  Ini:=TIniFile.Create(ExtractFilePath(ParamStr(0)) + 'Setup.ini');
  CompactContextMenu:=Ini.ReadBool('Main', 'CompactContextMenu', true);
  AddedControlPanel:=Ini.ReadBool('Main', 'ControlPanel', false);
  Ini.Free;

  SyncAppInfo;
  // Activate Drag and Drop
  DragAcceptFiles(Handle, true);
  ChangeWindowMessageFilterEx(Handle, WM_DROPFILES, MSGFLT_ALLOW, nil);
  ChangeWindowMessageFilterEx(Handle, WM_COPYDATA, MSGFLT_ALLOW, nil);
  ChangeWindowMessageFilterEx(Handle, $0049 {WM_COPYGLOBALDATA}, MSGFLT_ALLOW, nil);

  RuleNames:=TStringList.Create;
  RulePaths:=TStringList.Create;

  LoadRegRules;

  Event:=HandleParams();
  WND:=FindWindow('TMain', AppName);
  if WND <> 0 then begin
    if Event <> '' then
      SendMessageToHandle(WND, Event)
    else
      SetForegroundWindow(WND);
    CloseApplication:=true;
  end;

  if CloseApplication = false then
    Caption:=AppName;
  Application.Title:=Caption;
end;

procedure TMain.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  RuleNames.Free;
  RulePaths.Free;
end;

procedure TMain.CheckBtnClick(Sender: TObject);
var
  i: integer;
begin
  UnblockedCount:=0;
  for i:=RulePaths.Count - 1 downto 0 do
    if not FileExists(RulePaths.Strings[i]) then begin
      RemoveAppRules(RuleNames.Strings[i]);
      Inc(UnblockedCount);
    end;

  if UnblockedCount <> 0 then
    Status(IDS_REMOVED_RULES_FOR_NONEXISTENT_APPS + ' ' + IntToStr(UnblockedCount))
  else
    Status(IDS_RULES_FOR_NONEXISTENT_APPS_NOT_FOUND);
end;

procedure TMain.FormShow(Sender: TObject);
begin
  ListView.SetFocus;
  if CloseApplication then Close;
end;

procedure TMain.ListViewKeyUp(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  if ListView.ItemIndex = -1 then Exit;
  Status(CutStr(RulePaths.Strings[ListView.ItemIndex], 62));
  if Key = VK_DELETE then
    RemBtn.Click
  else if (Key = VK_RETURN) and (FileExists(RulePaths.Strings[ListView.ItemIndex])) then
    ShellExecute(0, 'open', 'explorer', PChar('/select, "' + RulePaths.Strings[ListView.ItemIndex] + '"'), nil, SW_SHOW);
end;

procedure TMain.WMCopyData(var Msg: TWMCopyData);
var
  Receiver: string;
begin
  Receiver:=PChar(TWMCopyData(Msg).CopyDataStruct.lpData);

  if Receiver = '%ADDED%' then begin
    Inc(BlockedCount);
    LoadRegRules;
    Status(IDS_RULES_SUCCESSFULLY_CREATED + ' ' + IntToStr(BlockedCount));
  end else if Receiver = '%REMOVED%' then begin
    Inc(UnblockedCount);
    LoadRegRules;
    Status(IDS_RULES_SUCCESSFULLY_REMOVED + ' ' + IntToStr(UnblockedCount));
  end else if (Receiver = '%EXISTS%') or (Receiver = '%ABSENT%') then
    Status(IDS_FAILED_CREATE_RULES)
  else if Receiver = '%MISSING%' then
    Status(IDS_FAILED_REMOVE_RULES)
  else if Receiver = '%IMPORTED%' then
    CheckBtn.Click;

  Msg.Result:=Integer(True);
end;

procedure TMain.ListViewKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  // Fixing the bug that hides controls / Убираем баг скрытия контролов
  if Key = VK_MENU then
    Key:=0;
end;

procedure TMain.FormKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  // Fixing the bug that hides controls / Убираем баг скрытия контролов
  if Key = VK_MENU then
    Key:=0;
end;

procedure TMain.ListViewDblClick(Sender: TObject);
begin
  if ListView.ItemIndex = -1 then Exit;
  if FileExists(RulePaths.Strings[ListView.ItemIndex]) then
    ShellExecute(0, 'open', 'explorer', PChar('/select, "' + RulePaths.Strings[ListView.ItemIndex] + '"'), nil, SW_SHOW);
end;

procedure ScrollToListViewItem(LV: TListview; ItemIndex: integer);
var
  R: TRect;
begin
  R:=LV.Items[ItemIndex].DisplayRect(drBounds);
  LV.Scroll(0, R.Top - LV.ClientHeight div 2);
end;

procedure TMain.SearchEdtChange(Sender: TObject);
var
  i: integer;
begin
  if ListView.Items.Count = 0 then Exit;
  ListView.ItemIndex:=-1;
  for i:=0 to RuleNames.Count - 1 do
    if Pos(AnsiLowerCase(SearchEdt.Text), AnsiLowerCase(RuleNames.Strings[i])) > 0 then begin

      ScrollToListViewItem(ListView, i);
      //ListView.ItemIndex:=i;
      ListView.Items.Item[i].Selected:=true;
      Break;
    end;
  if ListView.ItemIndex <> -1 then
    Status(CutStr(RulePaths.Strings[ListView.ItemIndex], 63))
  else
    Status();
end;

procedure TMain.SearchEdtKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  // Fixing the bug that hides controls / Убираем баг скрытия контролов
  if Key = VK_MENU then
    Key:=0;

  if SearchEdt.Text = IDS_SEARCH then begin
    SearchEdt.Font.Color:=clBlack;
    SearchEdt.Clear;
  end;
end;

procedure TMain.SearchEdtKeyUp(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  if SearchEdt.Text = '' then begin
    SearchEdt.Font.Color:=clGray;
    SearchEdt.Text:=IDS_SEARCH;
  end;
end;

procedure TMain.SearchEdtMouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: integer);
begin
  if SearchEdt.Text = IDS_SEARCH then begin
    SearchEdt.Font.Color:=clBlack;
    SearchEdt.Clear;
  end;
end;

procedure TMain.ImportBtnClick(Sender: TObject);
begin
  if ImportDialog.Execute then
    ImportRules(ImportDialog.FileName);
end;

procedure TMain.ExportBtnClick(Sender: TObject);
begin
  if ExportDialog.Execute then
    ExportRules(ExportDialog.FileName);
end;

procedure TMain.AboutBtnClick(Sender: TObject);
begin
  Application.MessageBox(PChar(Caption + ' ' + AppVersion + #13#10 +
  IDS_LAST_UPDATE + ' ' + AppUpdateDate + #13#10 +
  'https://r57zone.github.io' + #13#10 +
  'r57zone@gmail.com'), PChar(IDS_ABOUT), MB_ICONINFORMATION);
end;

procedure TMain.ListViewMouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: integer);
begin
  if ListView.ItemIndex <> -1 then begin
    Status(CutStr(RulePaths.Strings[ListView.ItemIndex], 62));
    if Button = mbRight then PopupMenu.Popup(Mouse.CursorPos.X, Mouse.CursorPos.Y);
  end else
    Status();

  if SearchEdt.Text = '' then begin
    SearchEdt.Font.Color:=clGray;
    SearchEdt.Text:=IDS_SEARCH;
  end;
end;

procedure TMain.RemBtn2Click(Sender: TObject);
begin
  RemBtn.Click;
end;

procedure TMain.ExportRules(const FilePath: string);
begin
  if RulePaths.Count > 0 then begin
    RulePaths.SaveToFile(FilePath);
    Status(IDS_RULES_SUCCESSFULLY_EXPORTED);
  end;
end;

procedure TMain.ImportRules(const FilePath: string);
var
  ImportRulesList: TStringList; i: integer;
begin
  if FileExists(FilePath) then begin
    CheckBtn.Click;
    ImportRulesList:=TStringList.Create;
    ImportRulesList.LoadFromFile(FilePath);

    BlockedCount:=0;
    for i:=0 to ImportRulesList.Count - 1 do
      if Pos(ImportRulesList.Strings[i], RulePaths.Text) = 0 then begin
        AddRulesForApp(ImportRulesList.Strings[i]);
        Inc(BlockedCount);
      end;

    Status(IDS_RULES_SUCCESSFULLY_IMPORTED);

    ImportRulesList.Free;
  end;
end;

procedure TMain.FileAssociation(const Recreate: boolean);
const
  RegKey = '\' + AppID + '.rules';
var
  Reg: TRegistry;
begin
  Reg:=TRegistry.Create;
  Reg.RootKey:=HKEY_CLASSES_ROOT;
  if Recreate and Reg.KeyExists(RegKey) then
    Reg.DeleteKey(RegKey);
  if (Reg.OpenKeyReadOnly(RegKey) = false) and Reg.OpenKey(RegKey, true) then begin
    Reg.WriteString('', AppName + ' Rules File');
    Reg.OpenKey(RegKey + '\DefaultIcon', true);
    Reg.WriteString('', '"' + ParamStr(0) + '",3');
    Reg.OpenKey(RegKey + '\Shell\Open\Command', true);
    Reg.WriteString('', '"' + ParamStr(0) + '" --import "%1"');
  end;
  Reg.CloseKey;
  Reg.Free;
end;

procedure TMain.FileExtension(const Recreate: boolean);
const
  RegKey = '\.fer';
var
  Reg: TRegistry;
begin
  Reg:=TRegistry.Create;
  Reg.RootKey:=HKEY_CLASSES_ROOT;
  if Recreate and Reg.KeyExists(RegKey) then
    Reg.DeleteKey(RegKey);
  if (Reg.OpenKeyReadOnly(RegKey) = false) and Reg.OpenKey(RegKey, true) then
    Reg.WriteString('', AppID + '.rules');
  Reg.CloseKey;
  Reg.Free;
end;

procedure TMain.SyncAppInfo;
var
  Reg: TRegistry;
  IsDifferent: boolean;
begin
  IsDifferent:=true;
  Reg:=TRegistry.Create;
  Reg.RootKey:=HKEY_LOCAL_MACHINE;
  if Reg.OpenKey('\Software\r57zone\' + AppID, true) then begin
    IsDifferent:=(Reg.ReadString('Path') <> ParamStr(0)) or (Reg.ReadString('Version') <> AppVersion) or (Reg.ReadString('Language') <> SystemLang);
    if IsDifferent then begin
      Reg.WriteString('Path', ParamStr(0));
      Reg.WriteString('Version', AppVersion);
      Reg.WriteString('Language', SystemLang);
    end;
    Reg.CloseKey;
  end;
  Reg.Free;
  ContextMenu(IsDifferent, CompactContextMenu);
  FileAssociation(IsDifferent);
  FileExtension(IsDifferent);
end;

procedure TMain.CloseBtnClick(Sender: TObject);
begin
  Close;
end;

procedure TMain.SettingsBtnClick(Sender: TObject);
begin
  Settings.Show;
end;

procedure TMain.CMDOptionsClick(Sender: TObject);
begin
  Application.MessageBox(PChar(IDS_COMMAND_LINE_OPTIONS_TEXT), PChar(IDS_COMMAND_LINE_OPTIONS), MB_ICONINFORMATION);
end;

procedure TMain.AddClassIdentifier;
const
  RegKey = '\SOFTWARE\Classes\CLSID\' + AppUUID;
var
  Reg: TRegistry;
begin
  Reg:=TRegistry.Create;
  try
    Reg.RootKey:=HKEY_LOCAL_MACHINE;
    Reg.Access:=KEY_ALL_ACCESS or KEY_WOW64_64KEY;

    if Reg.OpenKey(RegKey, True) then begin
      Reg.WriteString('', AppName);
      Reg.WriteString('InfoTip', IDS_INFO);
      Reg.WriteString('System.ApplicationName', 'r57zone.FirewallEasy');
      Reg.WriteString('System.ControlPanel.Category', '3');
    end;

    if Reg.OpenKey(RegKey + '\DefaultIcon', True) then
      Reg.WriteString('', ParamStr(0) + ',0');

    if Reg.OpenKey(RegKey + '\Shell\Open\Command', True) then
      Reg.WriteString('', '"' + ParamStr(0) + '"');

    Reg.CloseKey;
  finally
    Reg.Free;
  end;
end;

procedure TMain.RemoveClassIdentifier;
const
  RegKey = '\SOFTWARE\Classes\CLSID\' + AppUUID;
var
  Reg: TRegistry;
begin
  Reg:=TRegistry.Create;
  try
    Reg.RootKey:=HKEY_LOCAL_MACHINE;
    Reg.Access := KEY_ALL_ACCESS or KEY_WOW64_64KEY;
    if Reg.KeyExists(RegKey) then
      Reg.DeleteKey(RegKey);
  finally
    Reg.Free;
  end;
end;

procedure TMain.AddControlPanelEntry;
const
  RegKey = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\' + AppUUID;
var
  Reg: TRegistry;
begin
  Reg:=TRegistry.Create;
  try
    Reg.RootKey := HKEY_LOCAL_MACHINE;
    Reg.Access := KEY_ALL_ACCESS or KEY_WOW64_64KEY;
    if Reg.OpenKey(RegKey, True) then
      Reg.WriteString('', AppName);
    Reg.CloseKey;
  finally
    Reg.Free;
  end;
end;

procedure TMain.RemoveControlPanelEntry;
const
  RegKey = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\' + AppUUID;
var
  Reg: TRegistry;
begin
  Reg:=TRegistry.Create;
  try
    Reg.RootKey:=HKEY_LOCAL_MACHINE;
    Reg.Access := KEY_ALL_ACCESS or KEY_WOW64_64KEY;
    if Reg.KeyExists(RegKey) then
      Reg.DeleteKey(RegKey);
    Reg.CloseKey;
  finally
    Reg.Free;
  end;
end;

procedure TMain.DonateBtnClick(Sender: TObject);
begin
  ShellExecute(0, 'open', 'https://boosty.to/r57', nil, nil, SW_SHOWNORMAL);
end;

end.
