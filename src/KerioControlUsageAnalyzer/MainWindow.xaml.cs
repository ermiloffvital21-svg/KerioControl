using System.Windows;
using System.Windows.Controls;
using KerioControlUsageAnalyzer.ViewModels;

namespace KerioControlUsageAnalyzer;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;

    public MainWindow()
    {
        InitializeComponent();
        _viewModel = new MainViewModel();
        DataContext = _viewModel;
    }

    private void PasswordBox_OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox passwordBox)
        {
            _viewModel.Config.Password = passwordBox.Password;
        }
    }
}
