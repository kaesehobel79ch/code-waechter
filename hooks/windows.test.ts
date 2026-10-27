import { expect, test } from 'claude-code/testing'
import { csCrashErrors, resourceIndex, xamlErrors } from './windows'

// Prüfregeln für Windows-Programme (windows.ts). Jeder XAML-Fall hier wurde am 25.10.2026 von .NET 10 selbst beurteilt
// (XamlReader.Parse, danach Measure/Arrange, eigenes Probeprogramm): true = stürzt ab. Die Regeln müssen genau die Abstürze melden
// und keinen Wert, der läuft.

const NS = "xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'"

const XAML_CASES: [string, boolean][] = [
  ["<Grid NS><Button Width='12'/></Grid>", false],
  ["<Grid NS><Button Width='12.5'/></Grid>", false],
  ["<Grid NS><Button Width='1,5'/></Grid>", false],
  ["<Grid NS><Button Width='-3'/></Grid>", true],
  ["<Grid NS><Button Width='Auto'/></Grid>", false],
  ["<Grid NS><Button Width='auto'/></Grid>", false],
  ["<Grid NS><Button Width='NaN'/></Grid>", false],
  ["<Grid NS><Button Width='Infinity'/></Grid>", true],
  ["<Grid NS><Button Width='12px'/></Grid>", false],
  ["<Grid NS><Button Width='12 px'/></Grid>", false],
  ["<Grid NS><Button Width='1in'/></Grid>", false],
  ["<Grid NS><Button Width='2cm'/></Grid>", false],
  ["<Grid NS><Button Width='12pt'/></Grid>", false],
  ["<Grid NS><Button Width='12x'/></Grid>", true],
  ["<Grid NS><Button Width=''/></Grid>", false],
  ["<Grid NS><Button Width='  '/></Grid>", false],
  ["<Grid NS><Button Width='1e3'/></Grid>", false],
  ["<Grid NS><Button Width='+5'/></Grid>", false],
  ["<Grid NS><Button Width='.5'/></Grid>", false],
  ["<Grid NS><Button Width='5.'/></Grid>", false],
  ["<Grid NS><Button Width='1,5,6'/></Grid>", false],
  ["<Grid NS><Button Width='12PX'/></Grid>", false],
  ["<Grid NS><Button Width='0x10'/></Grid>", true],
  ["<Grid NS><Button Width='1.2.3'/></Grid>", true],
  ["<Grid NS><Button Width='12,'/></Grid>", false],
  ["<Grid NS><Button MaxWidth='12x'/></Grid>", true],
  ["<Grid NS><Button MaxWidth='12'/></Grid>", false],
  ["<Grid NS><Button MaxWidth='Auto'/></Grid>", true],
  ["<Grid NS><Button MaxWidth=''/></Grid>", false],
  ["<Grid NS><Button MaxWidth='Infinity'/></Grid>", false],
  ["<Grid NS><Button MaxWidth='NaN'/></Grid>", true],
  ["<Grid NS><Button MaxWidth='-1'/></Grid>", true],
  ["<Grid NS><Button MaxWidth='12px'/></Grid>", false],
  ["<Grid NS><Button MinWidth=''/></Grid>", false],
  ["<Grid NS><Button MinWidth='NaN'/></Grid>", true],
  ["<Grid NS><Button MinWidth='Infinity'/></Grid>", true],
  ["<Grid NS><Button MinWidth='5'/></Grid>", false],
  ["<Grid NS><TextBlock FontSize='12'/></Grid>", false],
  ["<Grid NS><TextBlock FontSize='Auto'/></Grid>", true],
  ["<Grid NS><TextBlock FontSize='0'/></Grid>", true],
  ["<Grid NS><TextBlock FontSize='-1'/></Grid>", true],
  ["<Grid NS><TextBlock FontSize='12pt'/></Grid>", false],
  ["<Grid NS><TextBlock FontSize='zwoelf'/></Grid>", true],
  ["<Grid NS><TextBlock FontSize='NaN'/></Grid>", true],
  ["<Grid NS><TextBlock FontSize='1.5'/></Grid>", false],
  ["<Grid NS><TextBlock FontSize=''/></Grid>", true],
  ["<Grid NS><TextBlock FontSize='1in'/></Grid>", false],
  ["<Grid NS><Canvas><Button Canvas.Left='12x'/></Canvas></Grid>", true],
  ["<Grid NS><Canvas><Button Canvas.Left='12'/></Canvas></Grid>", false],
  ["<Grid NS><Canvas><Button Canvas.Left=''/></Canvas></Grid>", false],
  ["<Grid NS><Canvas><Button Canvas.Left='Auto'/></Canvas></Grid>", false],
  ["<Grid NS><Canvas><Button Canvas.Left='NaN'/></Canvas></Grid>", false],
  ["<Grid NS><Canvas><Button Canvas.Left='-5'/></Canvas></Grid>", false],
  ["<Grid NS><Canvas><Button Canvas.Left='12px'/></Canvas></Grid>", false],
  ["<Grid NS><Rectangle StrokeThickness='x'/></Grid>", true],
  ["<Grid NS><Rectangle StrokeThickness='2'/></Grid>", false],
  ["<Grid NS><Rectangle StrokeThickness='Auto'/></Grid>", false],
  ["<Grid NS><Rectangle StrokeThickness=''/></Grid>", false],
  ["<Grid NS><Rectangle StrokeThickness='NaN'/></Grid>", false],
  ["<Grid NS><Rectangle StrokeThickness='-1'/></Grid>", false],
  ["<Grid NS><Rectangle StrokeThickness='1px'/></Grid>", false],
  ["<Grid NS><Button Opacity='0.5'/></Grid>", false],
  ["<Grid NS><Button Opacity='1'/></Grid>", false],
  ["<Grid NS><Button Opacity='50%'/></Grid>", true],
  ["<Grid NS><Button Opacity='0,5'/></Grid>", true],
  ["<Grid NS><Button Opacity=''/></Grid>", true],
  ["<Grid NS><Button Opacity='.5'/></Grid>", false],
  ["<Grid NS><Button Opacity='1e-1'/></Grid>", false],
  ["<Grid NS><Button Opacity='Auto'/></Grid>", true],
  ["<Grid NS><Button Opacity='-1'/></Grid>", false],
  ["<Grid NS><Button Opacity='2'/></Grid>", false],
  ["<Grid NS><Button Opacity='12px'/></Grid>", true],
  ["<Grid NS><Button Opacity='NaN'/></Grid>", false],
  ["<Grid NS><Button Opacity='Infinity'/></Grid>", false],
  ["<Grid NS><Button Opacity='-Infinity'/></Grid>", false],
  ["<Grid NS><Button Opacity=' 0.5 '/></Grid>", false],
  ["<Grid NS><Button Margin='1'/></Grid>", false],
  ["<Grid NS><Button Margin='1,2'/></Grid>", false],
  ["<Grid NS><Button Margin='1,2,3'/></Grid>", true],
  ["<Grid NS><Button Margin='1,2,3,4'/></Grid>", false],
  ["<Grid NS><Button Margin='1 2 3 4'/></Grid>", false],
  ["<Grid NS><Button Margin='1, 2'/></Grid>", false],
  ["<Grid NS><Button Margin='1,,2'/></Grid>", true],
  ["<Grid NS><Button Margin='4,x'/></Grid>", true],
  ["<Grid NS><Button Margin='Auto'/></Grid>", true],
  ["<Grid NS><Button Margin='1px,2'/></Grid>", false],
  ["<Grid NS><Button Margin=''/></Grid>", true],
  ["<Grid NS><Button Margin='1;2'/></Grid>", true],
  ["<Grid NS><Button Margin='-1,0'/></Grid>", false],
  ["<Grid NS><Button Margin='1.5,2.5'/></Grid>", false],
  ["<Grid NS><Button Margin='1,2,3,4,5'/></Grid>", true],
  ["<Grid NS><Button Margin='Auto,1'/></Grid>", true],
  ["<Grid NS><Button Margin='NaN'/></Grid>", true],
  ["<Grid NS><Button Margin='1 ,2'/></Grid>", false],
  ["<Grid NS><Button Margin='1in,2cm'/></Grid>", false],
  ["<Grid NS><Button Margin='1e2'/></Grid>", false],
  ["<Grid NS><Border Padding='x' BorderThickness='1'/></Grid>", true],
  ["<Grid NS><Border Padding='2,2' BorderThickness='1'/></Grid>", false],
  ["<Grid NS><Border BorderThickness='x'/></Grid>", true],
  ["<Grid NS><Border BorderThickness='1'/></Grid>", false],
  ["<Grid NS><Border CornerRadius='3'/></Grid>", false],
  ["<Grid NS><Border CornerRadius='1,2'/></Grid>", true],
  ["<Grid NS><Border CornerRadius='1,2,3,4'/></Grid>", false],
  ["<Grid NS><Border CornerRadius='1 2 3 4'/></Grid>", false],
  ["<Grid NS><Border CornerRadius='x'/></Grid>", true],
  ["<Grid NS><Border CornerRadius='1,2,3'/></Grid>", true],
  ["<Grid NS><Border CornerRadius='-1'/></Grid>", true],
  ["<Grid NS><Border CornerRadius='Auto'/></Grid>", true],
  ["<Grid NS><Border CornerRadius='1px'/></Grid>", true],
  ["<Grid NS><Border CornerRadius='1,2,3,4px'/></Grid>", true],
  ["<Grid NS><Button Grid.Row='0'/></Grid>", false],
  ["<Grid NS><Button Grid.Row='1'/></Grid>", false],
  ["<Grid NS><Button Grid.Row='-1'/></Grid>", true],
  ["<Grid NS><Button Grid.Row='a'/></Grid>", true],
  ["<Grid NS><Button Grid.Row='1.0'/></Grid>", true],
  ["<Grid NS><Button Grid.Row=' 2'/></Grid>", false],
  ["<Grid NS><Button Grid.Row='+1'/></Grid>", false],
  ["<Grid NS><Button Grid.Row='1e1'/></Grid>", true],
  ["<Grid NS><Button Grid.Row=''/></Grid>", true],
  ["<Grid NS><Button Grid.Row='2 '/></Grid>", false],
  ["<Grid NS><Button Grid.Row='00'/></Grid>", false],
  ["<Grid NS><Button Grid.Row='99999999999'/></Grid>", true],
  ["<Grid NS><Button Grid.RowSpan='0'/></Grid>", true],
  ["<Grid NS><Button Grid.RowSpan='-1'/></Grid>", true],
  ["<Grid NS><Button Grid.RowSpan='2'/></Grid>", false],
  ["<Grid NS><Button Grid.ColumnSpan='0'/></Grid>", true],
  ["<Grid NS><Button Grid.ColumnSpan='x'/></Grid>", true],
  ["<Grid NS><Button Panel.ZIndex='a'/></Grid>", true],
  ["<Grid NS><Button Panel.ZIndex='3'/></Grid>", false],
  ["<Grid NS><Button Panel.ZIndex='-5'/></Grid>", false],
  ["<Grid NS><Button Panel.ZIndex='+3'/></Grid>", false],
  ["<Grid NS><Button Panel.ZIndex=''/></Grid>", true],
  ["<Grid NS><Button TabIndex='a'/></Grid>", true],
  ["<Grid NS><Button TabIndex='5'/></Grid>", false],
  ["<Grid NS><Button TabIndex='-1'/></Grid>", false],
  ["<Grid NS><TextBox MaxLength='a'/></Grid>", true],
  ["<Grid NS><TextBox MaxLength='5'/></Grid>", false],
  ["<Grid NS><TextBox MaxLength='-1'/></Grid>", true],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='Auto'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='auto'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='*'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='2*'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='2**'/></Grid.RowDefinitions></Grid>", true],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='0.5*'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='100'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='100px'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='*2'/></Grid.RowDefinitions></Grid>", true],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='x'/></Grid.RowDefinitions></Grid>", true],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='1.5*'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height=' * '/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='2 *'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height=''/></Grid.RowDefinitions></Grid>", true],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='AUTO'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='-1'/></Grid.RowDefinitions></Grid>", true],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='1in'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='Auto*'/></Grid.RowDefinitions></Grid>", true],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='0'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='0*'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='.5*'/></Grid.RowDefinitions></Grid>", false],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='2px*'/></Grid.RowDefinitions></Grid>", true],
  ["<Grid NS><Grid.RowDefinitions><RowDefinition Height='  '/></Grid.RowDefinitions></Grid>", true],
  ["<Grid NS><Grid.ColumnDefinitions><ColumnDefinition Width='x'/></Grid.ColumnDefinitions></Grid>", true],
  ["<Grid NS><Grid.ColumnDefinitions><ColumnDefinition Width='2'/></Grid.ColumnDefinitions></Grid>", false],
  ["<Grid NS><Grid.ColumnDefinitions><ColumnDefinition Width='Auto'/></Grid.ColumnDefinitions></Grid>", false],
  ["<Grid NS><Grid.ColumnDefinitions><ColumnDefinition Width='2*'/></Grid.ColumnDefinitions></Grid>", false],
  ["<Grid NS><Grid.ColumnDefinitions><ColumnDefinition MinWidth='x'/></Grid.ColumnDefinitions></Grid>", true],
  ["<Grid NS><Grid.ColumnDefinitions><ColumnDefinition MinWidth='2'/></Grid.ColumnDefinitions></Grid>", false],
  ["<Grid NS><Grid.ColumnDefinitions><ColumnDefinition MinWidth='Auto'/></Grid.ColumnDefinitions></Grid>", true],
  ["<Grid NS><Button Background='Red'/></Grid>", false],
  ["<Grid NS><Button Background='red'/></Grid>", false],
  ["<Grid NS><Button Background='Rot'/></Grid>", true],
  ["<Grid NS><Button Background='#FFF'/></Grid>", false],
  ["<Grid NS><Button Background='#FFFF'/></Grid>", false],
  ["<Grid NS><Button Background='#FFFFFF'/></Grid>", false],
  ["<Grid NS><Button Background='#FFFFFFFF'/></Grid>", false],
  ["<Grid NS><Button Background='#12345'/></Grid>", true],
  ["<Grid NS><Button Background='#GGGGGG'/></Grid>", true],
  ["<Grid NS><Button Background='Transparent'/></Grid>", false],
  ["<Grid NS><Button Background='sc#1,0,0,0'/></Grid>", false],
  ["<Grid NS><Button Background=''/></Grid>", true],
  ["<Grid NS><Button Background='#fff'/></Grid>", false],
  ["<Grid NS><Button Background='RED'/></Grid>", false],
  ["<Grid NS><Button Background=' Red'/></Grid>", false],
  ["<Grid NS><Button Background='#1234567'/></Grid>", true],
  ["<Grid NS><Button Background='#FFFFFF '/></Grid>", false],
  ["<Grid NS><Button Background='DarkGrey'/></Grid>", true],
  ["<Grid NS><Button Background='DarkGray'/></Grid>", false],
  ["<Grid NS><Button Background='#aRgB'/></Grid>", true],
  ["<Grid NS><Button Background='transparent'/></Grid>", false],
  ["<Grid NS><Button Background='#ff'/></Grid>", true],
  ["<Grid NS><Button Foreground='Rot' BorderBrush='Red'/></Grid>", true],
  ["<Grid NS><Button Foreground='White' BorderBrush='Red'/></Grid>", false],
  ["<Grid NS><Button BorderBrush='Rot'/></Grid>", true],
  ["<Grid NS><Rectangle Fill='Rot' Stroke='Red'/></Grid>", true],
  ["<Grid NS><Rectangle Fill='Red' Stroke='Red'/></Grid>", false],
  ["<Grid NS><Rectangle Stroke='Rot'/></Grid>", true],
  ["<Grid NS><TextBox CaretBrush='Rot' SelectionBrush='Red'/></Grid>", true],
  ["<Grid NS><TextBox SelectionBrush='Rot'/></Grid>", true],
  ["<Grid NS><Button OpacityMask='Rot'/></Grid>", true],
  ["<Grid NS><Button><Button.Background><SolidColorBrush Color='Red'/></Button.Background></Button></Grid>", false],
  ["<Grid NS><Button><Button.Background><SolidColorBrush Color='#12345'/></Button.Background></Button></Grid>", true],
  ["<Grid NS><Button><Button.Background><SolidColorBrush Color='#FF00FF00'/></Button.Background></Button></Grid>", false],
  ["<Grid NS><Button><Button.Background><SolidColorBrush Color='Rot'/></Button.Background></Button></Grid>", true],
  ["<Grid NS><Button><Button.Background><SolidColorBrush Color=''/></Button.Background></Button></Grid>", true],
  ["<Grid NS><Button><Button.Background><SolidColorBrush Color='red'/></Button.Background></Button></Grid>", false],
  ["<Grid NS><Button><Button.Background><LinearGradientBrush><GradientStop Color='Rot' Offset='0'/></LinearGradientBrush></Button.Background></Button></Grid>", true],
  ["<Grid NS><Button><Button.Background><LinearGradientBrush><GradientStop Color='Red' Offset='0'/></LinearGradientBrush></Button.Background></Button></Grid>", false],
  ["<Grid NS><Button><Button.Effect><DropShadowEffect Color='Rot'/></Button.Effect></Button></Grid>", true],
  ["<Grid NS><Button><Button.Effect><DropShadowEffect Color='Red'/></Button.Effect></Button></Grid>", false],
  ["<Grid NS><TextBlock FontWeight='Bold'/></Grid>", false],
  ["<Grid NS><TextBlock FontWeight='bold'/></Grid>", false],
  ["<Grid NS><TextBlock FontWeight='Fett'/></Grid>", true],
  ["<Grid NS><TextBlock FontWeight='700'/></Grid>", false],
  ["<Grid NS><TextBlock FontWeight='SemiBold'/></Grid>", false],
  ["<Grid NS><TextBlock FontWeight='Regular'/></Grid>", false],
  ["<Grid NS><TextBlock FontWeight='1000'/></Grid>", true],
  ["<Grid NS><TextBlock FontWeight='0'/></Grid>", true],
  ["<Grid NS><TextBlock FontWeight='999'/></Grid>", false],
  ["<Grid NS><TextBlock FontWeight='1'/></Grid>", false],
  ["<Grid NS><TextBlock FontWeight='BOLD'/></Grid>", false],
  ["<Grid NS><TextBlock FontWeight=' Bold'/></Grid>", true],
  ["<Grid NS><TextBlock FontWeight=' 700'/></Grid>", false],
  ["<Grid NS><TextBlock FontWeight='700 '/></Grid>", false],
  ["<Grid NS><TextBlock FontStyle='Italic'/></Grid>", false],
  ["<Grid NS><TextBlock FontStyle='italic'/></Grid>", false],
  ["<Grid NS><TextBlock FontStyle='Kursiv'/></Grid>", true],
  ["<Grid NS><TextBlock FontStyle='Normal'/></Grid>", false],
  ["<Grid NS><TextBlock FontStyle=' Italic'/></Grid>", true],
  ["<Grid NS><TextBlock FontStyle='ITALIC'/></Grid>", false],
  ["<Grid NS><Button Visibility='Visible'/></Grid>", false],
  ["<Grid NS><Button Visibility='visible'/></Grid>", false],
  ["<Grid NS><Button Visibility='Unsichtbar'/></Grid>", true],
  ["<Grid NS><Button Visibility='Collapsed'/></Grid>", false],
  ["<Grid NS><Button Visibility='Hidden'/></Grid>", false],
  ["<Grid NS><Button Visibility='VISIBLE'/></Grid>", false],
  ["<Grid NS><Button Visibility=' Visible'/></Grid>", false],
  ["<Grid NS><Button Visibility='Visible '/></Grid>", false],
  ["<Grid NS><Button Visibility='2'/></Grid>", false],
  ["<Grid NS><Button Visibility='Visible,Hidden'/></Grid>", false],
  ["<Grid NS><Button Visibility=''/></Grid>", true],
  ["<Grid NS><Button Visibility=' '/></Grid>", true],
  ["<Grid NS><Button HorizontalAlignment='Left'/></Grid>", false],
  ["<Grid NS><Button HorizontalAlignment='Center'/></Grid>", false],
  ["<Grid NS><Button HorizontalAlignment='Centre'/></Grid>", true],
  ["<Grid NS><Button HorizontalAlignment='Stretch'/></Grid>", false],
  ["<Grid NS><Button HorizontalAlignment='right'/></Grid>", false],
  ["<Grid NS><Button HorizontalContentAlignment='Centre'/></Grid>", true],
  ["<Grid NS><Button HorizontalContentAlignment='Center'/></Grid>", false],
  ["<Grid NS><Button VerticalAlignment='Mitte'/></Grid>", true],
  ["<Grid NS><Button VerticalAlignment='Top'/></Grid>", false],
  ["<Grid NS><Button VerticalContentAlignment='Mitte'/></Grid>", true],
  ["<Grid NS><Button VerticalContentAlignment='Bottom'/></Grid>", false],
  ["<Grid NS><TextBlock TextAlignment='Mitte'/></Grid>", true],
  ["<Grid NS><TextBlock TextAlignment='Justify'/></Grid>", false],
  ["<Grid NS><TextBlock TextWrapping='Wrap'/></Grid>", false],
  ["<Grid NS><TextBlock TextWrapping='WrapWithOverflow'/></Grid>", false],
  ["<Grid NS><TextBlock TextWrapping='NoWrap'/></Grid>", false],
  ["<Grid NS><TextBlock TextWrapping='Umbruch'/></Grid>", true],
  ["<Grid NS><TextBlock TextTrimming='x'/></Grid>", true],
  ["<Grid NS><TextBlock TextTrimming='WordEllipsis'/></Grid>", false],
  ["<Grid NS><StackPanel Orientation='quer'/></Grid>", true],
  ["<Grid NS><StackPanel Orientation='Horizontal'/></Grid>", false],
  ["<Grid NS><Image Stretch='x'/></Grid>", true],
  ["<Grid NS><Image Stretch='Uniform'/></Grid>", false],
  ["<Grid NS><ScrollViewer VerticalScrollBarVisibility='x'/></Grid>", true],
  ["<Grid NS><ScrollViewer VerticalScrollBarVisibility='Auto'/></Grid>", false],
  ["<Grid NS><ScrollViewer HorizontalScrollBarVisibility='x'/></Grid>", true],
  ["<Grid NS><ScrollViewer HorizontalScrollBarVisibility='Disabled'/></Grid>", false],
  ["<Grid NS><ListBox ScrollViewer.VerticalScrollBarVisibility='x'/></Grid>", true],
  ["<Grid NS><ListBox ScrollViewer.VerticalScrollBarVisibility='Hidden'/></Grid>", false],
  ["<Grid NS><DockPanel><Button DockPanel.Dock='x'/></DockPanel></Grid>", true],
  ["<Grid NS><DockPanel><Button DockPanel.Dock='Top'/></DockPanel></Grid>", false],
  ["<Grid NS><Button IsEnabled='True'/></Grid>", false],
  ["<Grid NS><Button IsEnabled='true'/></Grid>", false],
  ["<Grid NS><Button IsEnabled='False'/></Grid>", false],
  ["<Grid NS><Button IsEnabled='Ja'/></Grid>", true],
  ["<Grid NS><Button IsEnabled='1'/></Grid>", true],
  ["<Grid NS><Button IsEnabled='yes'/></Grid>", true],
  ["<Grid NS><Button IsEnabled='TRUE'/></Grid>", false],
  ["<Grid NS><Button IsEnabled=' True'/></Grid>", false],
  ["<Grid NS><Button IsEnabled=''/></Grid>", true],
  ["<Grid NS><Button Focusable='Ja' IsTabStop='True'/></Grid>", true],
  ["<Grid NS><Button Focusable='False' IsTabStop='True'/></Grid>", false],
  ["<Grid NS><Button IsTabStop='Ja'/></Grid>", true],
  ["<Grid NS><Button IsDefault='Ja'/></Grid>", true],
  ["<Grid NS><Button IsCancel='Ja'/></Grid>", true],
  ["<Grid NS><Button ClipToBounds='Ja'/></Grid>", true],
  ["<Grid NS><Button SnapsToDevicePixels='Ja'/></Grid>", true],
  ["<Grid NS><Button UseLayoutRounding='Ja'/></Grid>", true],
  ["<Grid NS><Button IsHitTestVisible='Ja'/></Grid>", true],
  ["<Grid NS><Button AllowDrop='Ja'/></Grid>", true],
  ["<Grid NS><TextBox IsReadOnly='Ja' AcceptsReturn='True' AcceptsTab='True'/></Grid>", true],
  ["<Grid NS><TextBox IsReadOnly='True' AcceptsReturn='True' AcceptsTab='True'/></Grid>", false],
  ["<Grid NS><TextBox AcceptsReturn='Ja'/></Grid>", true],
  ["<Grid NS><TextBox AcceptsTab='Ja'/></Grid>", true],
  ["<Grid NS><CheckBox IsThreeState='Ja'/></Grid>", true],
  ["<Grid NS><CheckBox IsChecked='True'/></Grid>", false],
  ["<Grid NS><CheckBox IsChecked='False'/></Grid>", false],
  ["<Grid NS><CheckBox IsChecked='Ja'/></Grid>", true],
  ["<Grid NS><CheckBox IsChecked=''/></Grid>", false],
  ["<Grid NS><ComboBox IsEditable='Ja'/></Grid>", true],
  ["<Grid NS><ComboBox IsTextSearchEnabled='Ja'/></Grid>", true],
  ["<Grid NS><Grid ShowGridLines='Ja'/></Grid>", true],
  ["<Grid NS><ProgressBar IsIndeterminate='Ja'/></Grid>", true],
  ["<Grid NS><Popup StaysOpen='Ja'/></Grid>", true],
  ["<Grid NS><Button FrameworkElement.Width='12x'/></Grid>", true],
  ["<Grid NS><Button FrameworkElement.Width='12'/></Grid>", false],
  ["<Grid NS><Grid TextElement.FontSize='x'/></Grid>", true],
  ["<Grid NS><Grid TextElement.FontSize='12'/></Grid>", false],
  ["<Grid NS><Grid TextElement.FontWeight='x'/></Grid>", true],
  ["<Grid NS><Grid TextElement.FontWeight='Bold'/></Grid>", false],
  ["<Grid NS><Grid TextElement.FontStyle='x'/></Grid>", true],
  ["<Grid NS><Grid TextElement.FontStyle='Italic'/></Grid>", false],
  ["<Grid NS><Grid TextElement.Foreground='Rot'/></Grid>", true],
  ["<Grid NS><Grid TextElement.Foreground='Red'/></Grid>", false],
  ["<Grid NS><Grid TextBlock.FontSize='x'/></Grid>", true],
  ["<Grid NS><Grid TextBlock.FontWeight='x'/></Grid>", true],
  ["<Grid NS><Grid TextBlock.Foreground='Rot'/></Grid>", true],
  ["<Grid NS><DataGrid><DataGrid.Columns><DataGridTextColumn Width='SizeToHeader'/></DataGrid.Columns></DataGrid></Grid>", false],
  ["<Grid NS><DataGrid><DataGrid.Columns><DataGridTextColumn Width='*'/></DataGrid.Columns></DataGrid></Grid>", false],
  ["<Grid NS><DataGrid><DataGrid.Columns><DataGridTextColumn Width='2*'/></DataGrid.Columns></DataGrid></Grid>", false],
  ["<Grid NS><DataGrid><DataGrid.Columns><DataGridTextColumn Width='100'/></DataGrid.Columns></DataGrid></Grid>", false],
  ["<Grid NS><ListView><ListView.View><GridView><GridViewColumn Width='Auto'/></GridView></ListView.View></ListView></Grid>", false],
  ["<Grid NS><ListView><ListView.View><GridView><GridViewColumn Width='100'/></GridView></ListView.View></ListView></Grid>", false],
  ["<Grid NS><Grid.Resources><Style x:Key='S' TargetType='Button'><Setter Property='Width' Value='12x'/></Style></Grid.Resources></Grid>", true],
  ["<Grid NS><Grid.Resources><Style x:Key='S' TargetType='Button'><Setter Property='Width' Value='12'/></Style></Grid.Resources></Grid>", false],
  ["<Grid NS><Grid.Resources><Style x:Key='S' TargetType='Button'><Setter Property='Width' Value='Auto'/></Style></Grid.Resources></Grid>", false],
  ["<Grid NS><Grid.Resources><Style x:Key='S' TargetType='Button'><Setter Property='Control.Width' Value='12x'/></Style></Grid.Resources></Grid>", true],
  ["<Grid NS><Grid.Resources><Style x:Key='S' TargetType='Button'><Setter Property='Control.Width' Value='12'/></Style></Grid.Resources></Grid>", false],
  ["<Grid NS><Grid.Resources><Style x:Key='S' TargetType='{x:Type Button}'><Setter Property='Background' Value='Rot'/></Style></Grid.Resources></Grid>", true],
  ["<Grid NS><Grid.Resources><Style x:Key='S' TargetType='{x:Type Button}'><Setter Property='Background' Value='Red'/></Style></Grid.Resources></Grid>", false],
  ["<Grid NS><Grid.Resources><Style x:Key='S' TargetType='Button'><Setter Property='Grid.Row' Value='a'/></Style></Grid.Resources></Grid>", true],
  ["<Grid NS><Grid.Resources><Style x:Key='S' TargetType='Button'><Setter Property='Grid.Row' Value='1'/></Style></Grid.Resources></Grid>", false],
  ["<Grid NS><Grid.Resources><Style x:Key='S' TargetType='RowDefinition'><Setter Property='Height' Value='x'/></Style></Grid.Resources></Grid>", true],
  ["<Grid NS><Grid.Resources><Style x:Key='S' TargetType='RowDefinition'><Setter Property='Height' Value='2*'/></Style></Grid.Resources></Grid>", false],
  ["<Grid NS><Grid.Resources><Style x:Key='S' TargetType='Button'><Style.Triggers><Trigger Property='IsMouseOver' Value='True'><Setter Property='Background' Value='Rot'/></Trigger></Style.Triggers></Style></Grid.Resources></Grid>", true],
  ["<Grid NS><Grid.Resources><Style x:Key='S' TargetType='Button'><Style.Triggers><Trigger Property='IsMouseOver' Value='True'><Setter Property='Background' Value='Red'/></Trigger></Style.Triggers></Style></Grid.Resources></Grid>", false],
  ["<Grid NS><Grid.Resources><SolidColorBrush x:Key='B' Color='Red'/></Grid.Resources><Button Background='{StaticResource B}'/></Grid>", false],
  ["<Grid NS><Grid.Resources><SolidColorBrush x:Key='B' Color='Red'/></Grid.Resources><Button Background='{StaticResource Nope}'/></Grid>", true],
  ["<Grid NS><Grid.Resources><SolidColorBrush x:Key='B' Color='Red'/></Grid.Resources><Button Background='{StaticResource ResourceKey=B}'/></Grid>", false],
  ["<Grid NS><Grid.Resources><SolidColorBrush x:Key='B' Color='Red'/></Grid.Resources><Button Background='{StaticResource ResourceKey=Nope}'/></Grid>", true],
  ["<Grid NS><Grid.Resources><Style x:Key='Text' TargetType='Button'/></Grid.Resources><Button Background='{StaticResource Text}'/></Grid>", true],
  ["<Grid NS><TextBlock Text='{Binding Source=1, Converter={StaticResource Nope}}'/></Grid>", true],
  ["<Grid NS><Button Background='{DynamicResource Nope}'/></Grid>", false],
  ["<Window NS Topmost='Ja'/>", true],
  ["<Window NS Topmost='True'/>", false],
  ["<Window NS ShowInTaskbar='Ja'/>", true],
  ["<Window NS ShowInTaskbar='False'/>", false],
  ["<Window NS ResizeMode='x'/>", true],
  ["<Window NS ResizeMode='NoResize'/>", false],
  ["<Window NS WindowStartupLocation='Mitte'/>", true],
  ["<Window NS WindowStartupLocation='CenterScreen'/>", false],
  ["<Window NS SizeToContent='x'/>", true],
  ["<Window NS SizeToContent='WidthAndHeight'/>", false],
  ["<Window NS WindowState='x'/>", true],
  ["<Window NS WindowState='Maximized'/>", false],
  ["<Window NS WindowStyle='x'/>", true],
  ["<Window NS WindowStyle='ToolWindow'/>", false],
  ["<Window NS Width='12x'/>", true],
  ["<Window NS Width='400'/>", false],
]

test('XAML: jeder von .NET gemessene Absturz wird gemeldet, kein laufender Wert', () => {
  const wrong: string[] = []
  for (const [snippet, crashes] of XAML_CASES) {
    const xaml = snippet.replace('NS', NS)
    const found = xamlErrors(xaml, 'C:\\p\\F.xaml', resourceIndex('P', [{ text: xaml }], []))
    if ((found.length > 0) !== crashes) wrong.push(`${crashes ? 'nicht gemeldet' : 'Fehlalarm'}: ${snippet} ${found.map(f => f.text).join(' | ')}`)
  }
  expect(wrong).toEqual([])
  expect(XAML_CASES.length).toBe(360)
  expect(XAML_CASES.filter(c => c[1]).length).toBe(159)
})

const wpf = (body: string): string => `<Window ${NS}>\n${body}\n</Window>`

test('XAML: Zeile, Code und Datei stimmen', () => {
  const f = xamlErrors(wpf('<Grid>\n  <Button Width="12x"/>\n</Grid>'), 'C:\\p\\F.xaml')
  expect(f.length).toBe(1)
  expect(f[0].line).toBe(3)
  expect(f[0].code).toBe('CW-XAML-WERT')
  expect(f[0].file).toBe('C:\\p\\F.xaml')
})

test('XAML: Ressourcen aus App.xaml und aus dem Code gelten, ein fehlender Name wird gemeldet', () => {
  const app = `<Application ${NS}><Application.Resources><SolidColorBrush x:Key="Akzent" Color="#FFB547"/></Application.Resources></Application>`
  const code = 'Resources["AusCode"] = new SolidColorBrush(Colors.Red);'
  const win = wpf('<StackPanel><Button Background="{StaticResource Akzent}"/><Button Background="{StaticResource AusCode}"/><Button Foreground="{StaticResource Fehlt}"/></StackPanel>')
  const index = resourceIndex('P', [{ text: app }, { text: win }], [{ text: code }])
  const f = xamlErrors(win, 'C:\\p\\W.xaml', index)
  expect(f.map(x => x.code)).toEqual(['CW-XAML-RESSOURCE'])
  expect(f[0].text).toContain('Fehlt')
})

test('XAML: ohne lesbare Namen (fremde Bibliothek, Name aus Variable) wird kein fehlender Name gemeldet', () => {
  const win = wpf('<Button Background="{StaticResource Fehlt}"/>')
  const fremd = `<Application ${NS}><Application.Resources><ResourceDictionary><ResourceDictionary.MergedDictionaries><ResourceDictionary Source="pack://application:,,,/Fremd.Themen;component/Farben.xaml"/></ResourceDictionary.MergedDictionaries></ResourceDictionary></Application.Resources></Application>`
  expect(xamlErrors(win, 'W.xaml', resourceIndex('P', [{ text: fremd }, { text: win }], []))).toEqual([])
  expect(xamlErrors(win, 'W.xaml', resourceIndex('P', [{ text: win }], [{ text: 'Resources[name] = b;' }]))).toEqual([])
  const eigen = fremd.replace('Fremd.Themen', 'P')
  expect(xamlErrors(win, 'W.xaml', resourceIndex('P', [{ text: eigen }, { text: win }], [])).length).toBe(1)
})

test('XAML: Stil im Fenster verdeckt die gleich heissende Farbe aus App.xaml (gemessener Absturz eines WPF-Programms)', () => {
  const app = `<Application ${NS}><Application.Resources><SolidColorBrush x:Key="Text" Color="White"/></Application.Resources></Application>`
  const win = wpf('<Window.Resources><Style x:Key="Text" TargetType="TextBlock"/></Window.Resources><Button Foreground="{StaticResource Text}"/>')
  const f = xamlErrors(win, 'W.xaml', resourceIndex('P', [{ text: app }, { text: win }], []))
  expect(f.map(x => x.code)).toEqual(['CW-XAML-STIL'])
  expect(xamlErrors(wpf('<Button Foreground="{StaticResource Text}"/>'), 'W.xaml', resourceIndex('P', [{ text: app }], []))).toEqual([])
})

test('XAML: eigene Steuerelemente, andere Oberflächen und markierte Stellen bleiben ungeprüft', () => {
  expect(xamlErrors(wpf('<local:Kachel xmlns:local="clr-namespace:P" Width="12x"/>'), 'W.xaml')).toEqual([])
  expect(xamlErrors('<ContentPage xmlns="http://schemas.microsoft.com/dotnet/2021/maui"><Button WidthRequest="x" Margin="1,2,3"/></ContentPage>', 'M.xaml')).toEqual([])
  expect(xamlErrors(wpf('<Button Width="12x"/> <!-- code-waechter:ok CW-XAML-WERT -->'), 'W.xaml')).toEqual([])
  expect(xamlErrors(wpf('<Button Width="{Binding Breite}" Margin="{StaticResource Rand}"/>'), 'W.xaml')).toEqual([])
})

const cs = (body: string): string => `using System;\nusing System.Globalization;\nclass K\n{\n    void M(DateTime zeit, TextBox Eingabe, string t, CultureInfo inv, bool a)\n    {\n${body}\n    }\n}\n`
const codes = (body: string): string[] => csCrashErrors(cs(body), 'C:\\p\\K.cs').map(f => f.code)

test('C#: ein einzelner Buchstabe als Format, gemessen an .NET', () => {
  // stürzt ab (gemessen)
  for (const bad of [
    'var s = DateTime.Now.ToString("H");',
    'var s = zeit.ToString("H", inv);',
    'var s = DateTime.Now.ToString("N");',
    'var s = $"{zeit:H} Uhr";',
    'var s = $@"{zeit:H}";',
    'var s = $"{DateTime.Now:N}";',
    'var s = $"{global::System.DateTime.Now:H}";',
    'var s = string.Format("{0:H}", zeit);',
    'var s = string.Format(inv, "Um {0,5:h}", zeit);',
    'var d = DateTime.ParseExact(t, "H", inv);',
    'DateTime.TryParseExact(t, "H", inv, DateTimeStyles.None, out var d);',
    'var d = TimeSpan.ParseExact(t, "h", inv);',
    'var s = 5.ToString("Q");',
  ]) expect([bad, codes(bad)]).toEqual([bad, ['CW-FORMAT']])
  // läuft (gemessen oder gültiges Kurzformat)
  for (const good of [
    'var s = zeit.ToString("%H");',
    'var s = zeit.ToString("HH:mm");',
    'var s = x.ToString("N");',
    'var s = DateTime.Now.ToString("d");',
    'var s = $"{zeit:HH} Uhr";',
    'var s = $"{zeit:%H} Uhr";',
    'var s = $"{(a ? 1 : 2)}";',
    'var s = $"{{zeit:H}}";',
    'var s = string.Format("{{0:H}}", zeit);',
    'var d = DateTime.ParseExact(t, "%H", inv);',
    'var d = TimeSpan.ParseExact(t, "c", inv);',
    '// var s = zeit.ToString("H");',
    'var s = "zeit.ToString(\\"H\\")";',
    'var s = zeit.ToString("H"); // code-waechter:ok CW-FORMAT',
  ]) expect([good, codes(good)]).toEqual([good, []])
})

test('C#: Formatlisten bei ParseExact, auch über eine Variable (gemessener Absturz eines WPF-Programms)', () => {
  // So stand es in einem echten Programm: "14:30" lief, jede andere Eingabe stürzte ab (gemessen)
  const easy = `class D\n{\n    private static readonly string[] ZeitFormen = { "H:mm", "HH:mm", "H.mm", "HH.mm", "H" };\n    bool Lies(string t, out DateTime z) => DateTime.TryParseExact(t.Trim(), ZeitFormen, CultureInfo.InvariantCulture, DateTimeStyles.None, out z);\n}\n`
  const f = csCrashErrors(easy, 'C:\\p\\Daten.cs')
  expect(f.map(x => [x.code, x.line])).toEqual([['CW-FORMAT', 3]])
  expect(csCrashErrors(easy.replace('"H" }', '"%H" }'), 'C:\\p\\Daten.cs')).toEqual([])
  expect(codes('var d = DateTime.ParseExact(t, new[] { "HH:mm", "H" }, inv, DateTimeStyles.None);')).toEqual(['CW-FORMAT'])
  expect(codes('string[] f = ["HH:mm", "H"]; DateTime.TryParseExact(t, f, inv, DateTimeStyles.None, out var d);')).toEqual(['CW-FORMAT'])
  expect(codes('string f = "H"; var d = DateTime.ParseExact(t, f, inv);')).toEqual(['CW-FORMAT'])
  expect(codes('var d = DateTime.ParseExact(t, new[] { "HH:mm", "%H", "d" }, inv, DateTimeStyles.None);')).toEqual([])
})

test('C#: Parse auf eine Eingabe der Oberfläche stürzt bei leerem Feld ab, TryParse und try nicht', () => {
  expect(codes('int n = int.Parse(Eingabe.Text);')).toEqual(['CW-PARSE'])
  expect(codes('int n = Convert.ToInt32(Eingabe.Text.Trim());')).toEqual(['CW-PARSE'])
  expect(codes('var d = decimal.Parse(Eingabe.Text, inv);')).toEqual(['CW-PARSE'])
  expect(codes('try { int n = int.Parse(Eingabe.Text); } catch (FormatException) { }')).toEqual([])
  expect(codes('if (int.TryParse(Eingabe.Text, out int n)) { }')).toEqual([])
  expect(codes('int n = int.Parse(t);')).toEqual([])
  expect(codes('int n = int.Parse(Eingabe.Text); // code-waechter:ok CW-PARSE')).toEqual([])
  const f = csCrashErrors(cs('int n = int.Parse(Eingabe.Text);'), 'C:\\p\\K.cs')
  expect(f[0].line).toBe(7)
})