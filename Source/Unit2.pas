unit Unit2;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, IniFiles, ExtCtrls;

type
  TSettings = class(TForm)
    AddUnblockContextMenuCB: TCheckBox;
    Panel: TPanel;
    ApplyBtn: TButton;
    CancelBtn: TButton;
    AddControlPanelCB: TCheckBox;
    procedure ApplyBtnClick(Sender: TObject);
    procedure CancelBtnClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Settings: TSettings;

implementation

uses Unit1;

{$R *.dfm}

procedure TSettings.ApplyBtnClick(Sender: TObject);
var
  Ini: TIniFile;
begin
  Ini:=TIniFile.Create(ExtractFilePath(ParamStr(0)) + 'Setup.ini');
  Main.CompactContextMenu:=not AddUnblockContextMenuCB.Checked;
  Ini.WriteBool('Main', 'CompactContextMenu', Main.CompactContextMenu);
  Main.AddedControlPanel:=AddControlPanelCB.Checked;
  Ini.WriteBool('Main', 'ControlPanel', Main.AddedControlPanel);
  Ini.Free;
  Main.ContextMenu(true, Main.CompactContextMenu);
  if Main.AddedControlPanel then begin
    Main.AddClassIdentifier;
    Main.AddControlPanelEntry;
  end else begin
    Main.RemoveControlPanelEntry;
    Main.RemoveClassIdentifier;
  end;
  Close;
end;

procedure TSettings.CancelBtnClick(Sender: TObject);
begin
  Close;
end;

procedure TSettings.FormCreate(Sender: TObject);
begin
  Caption:=Main.SettingsBtn.Caption;
  AddUnblockContextMenuCB.Caption:=IDS_UNBLOCK_ACCESS_CONTEXT_MENU;
  AddControlPanelCB.Caption:=IDS_ADD_TO_CONTROL_PANEL;
  ApplyBtn.Caption:=IDS_APPLY;
  CancelBtn.Caption:=IDS_CANCEL;

  AddUnblockContextMenuCB.Checked:=not Main.CompactContextMenu;
  AddControlPanelCB.Checked:=Main.AddedControlPanel;
end;

end.
