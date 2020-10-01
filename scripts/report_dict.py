report_dict = {
    'Application Control': {
        'Maturity Level 1': {
            'Control 1': {
                'Control Name': 'Application control is implemented on all workstations to restrict the execution of executables to an approved set.',
                'Policy Name': 'Don\'t run specified Windows applications',
                'Policy Location': 'User Configuration > Administrative Templates > Systems',
                'Policy Script': None,
                'Policy Actions': 'Configure a list of .exe applications that all workstations have the ability to install safely.',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Application control is implemented on all servers to restrict the execution of executables to an approved set.',
                'Policy Name': 'Don\'t run specified Windows applications',
                'Policy Location': 'User Configuration > Administrative Templates > Systems',
                'Policy Script': None,
                'Policy Actions': 'Configure a list of .exe applications that all servers have the ability to install safely.',
                'Policy Score': 0
            }
        },
        'Maturity Level 2': {
            'Control 1': {
                'Control Name': 'Application control is implemented on all workstations to restrict the execution of executables, software libraries, scripts and installers to an approved set.',
                'Policy Name': 'Don\'t run specified Windows applications',
                'Policy Location': 'User Configuration > Administrative Templates > Systems',
                'Policy Script': None,
                'Policy Actions': 'Configure a list of .exe, .ps1, .dll applications that all workstations have the ability to install safely.',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Application control is implemented on all servers to restrict the execution of executables, software libraries, scripts and installers to an approved set.',
                'Policy Name': 'Don\'t run specified Windows applications',
                'Policy Location': 'User Configuration > Administrative Templates > Systems',
                'Policy Script': None,
                'Policy Actions': 'Configure a list of .exe, .ps1, .dll applications that all servers have the ability to install safely.',
                'Policy Score': 0
            }
        },
        'Maturity Level 3': {
            'Control 1': {
                'Control Name': 'Application control is implemented on all workstations to restrict the execution of executables, software libraries, scripts and installers to an approved set.',
                'Policy Name': 'Don\'t run specified Windows applications',
                'Policy Location': 'User Configuration > Administrative Templates > Systems',
                'Policy Script': None,
                'Policy Actions': 'Configure a list of .exe, .ps1, .dll applications that all workstations have the ability to install safely.',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Application control is implemented on all servers to restrict the execution of executables, software libraries, scripts and installers to an approved set.',
                'Policy Name': 'Don\'t run specified Windows applications',
                'Policy Location': 'User Configuration > Administrative Templates > Systems',
                'Policy Script': None,
                'Policy Actions': 'Configure a list of .exe, .ps1, .dll applications that all servers have the ability to install safely.',
                'Policy Score': 0
            },
            'Control 3': {
                'Control Name': 'Microsoft’s latest recommended block rules are implemented to prevent application control bypasses.',
                'Policy Name': 'Don\'t run specified Windows applications',
                'Policy Location': 'User Configuration > Administrative Templates > Systems',
                'Policy Script': None,
                'Policy Actions': 'Ensure all of the following files are added to the block list: addinprocess.exe, addinprocess32.exe, addinutil.exe, aspnet_compiler.exe, bash.exe, bginfo.exe, cdb.exe, csi.exe, dbghost.exe, dbgsvc.exe, dnx.exe, dotnet.exe, fsi.exe, fsiAnyCpu.exe, infdefaultinstall.exe, kd.exe, kill.exe, lxssmanager.dll, lxrun.exe, Microsoft.Build.dll, Microsoft.Build.Framework.dll, Microsoft.Workflow.Compiler.exe, msbuild.exe, msbuild.dll, mshta.exe, ntkd.exe, ntsd.exe, powershellcustomhost.exe, rcsi.exe, runscripthelper.exe, texttransform.exe, visualuiaverifynative.exe, system.management.automation.dll, wfc.exe, windbg.exe, wmic.exe, wsl.exe, wslconfig.exe, wslhost.exe',
                'Policy Score': 0
            }
        },
    },
    # 'Patch Applications': {
    #     'Maturity Level 1': {
    #         'Control 1': {
    #             'Control Name': ,
    #             'Policy Name': '',
    #             'Policy Location': ,
    #             'Policy Script': ,
    #             'Policy Actions': ,
    #             'Policy Score':
    #         },
    #         'Control 2': {
    #             'Control Name': ,
    #             'Policy Name': '',
    #             'Policy Location': ,
    #             'Policy Script': ,
    #             'Policy Actions': ,
    #             'Policy Score':
    #         }
    #     },
    #     'Maturity Level 2': {
    #         'Control 1': {
    #             'Control Name': ,
    #             'Policy Name': '',
    #             'Policy Location': ,
    #             'Policy Script': ,
    #             'Policy Actions': ,
    #             'Policy Score':
    #         },
    #         'Control 2': {
    #             'Control Name': ,
    #             'Policy Name': '',
    #             'Policy Location': ,
    #             'Policy Script': ,
    #             'Policy Actions': ,
    #             'Policy Score':
    #         }
    #     },
    #     'Maturity Level 3': {
    #         'Control 1': {
    #             'Control Name': ,
    #             'Policy Name': '',
    #             'Policy Location': ,
    #             'Policy Script': ,
    #             'Policy Actions': ,
    #             'Policy Score':
    #         },
    #         'Control 2': {
    #             'Control Name': ,
    #             'Policy Name': '',
    #             'Policy Location': ,
    #             'Policy Script': ,
    #             'Policy Actions': ,
    #             'Policy Score':
    #         },
    #         'Control 3': {
    #             'Control Name': ,
    #             'Policy Name': '',
    #             'Policy Location': ,
    #             'Policy Script': ,
    #             'Policy Actions': ,
    #             'Policy Score':
    #         }
    #     }
    # },
    'Microsoft Office Macros': {
        'Maturity Level 1': {
            'Control 1': {
                'Control Name': 'Microsoft Office macros are allowed to execute, but only after prompting users for approval.',
                'Policy Name': 'Disable Trust Bar Notification for Unsigned application add-ins and block them (Disable)',
                'Policy Location': 'User Configuration\Policies\Administration Templates\Microsoft Office 2016\Security Settings',
                'Policy Script': None,
                'Policy Actions': 'Ensure documents are opened in view only mode and macros are only run with user approval.',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Microsoft Office macro security settings cannot be changed by users.',
                'Policy Name': 'Automation Security',
                'Policy Location': 'User Configuration\Policies\Administration Templates\Microsoft Office 2012\Security Settings',
                'Policy Script': None,
                'Policy Actions': 'Configure Automation Security to ensure that users are unbale to change macro security settings, helps to stop privilage escilation attacks',
                'Policy Score': 0
            }
        },
        'Maturity Level 2': {
            'Control 1': {
                'Control Name': 'Only signed Microsoft Office macros are allowed to execute.',
                'Policy Name': 'Allow mix of policy and user locations',
                'Policy Location': 'User Configuration\Policies\Administration Templates\Microsoft Office 2016\Security Settings\Trust Center',
                'Policy Script': None,
                'Policy Actions': 'Configure the policy to only run macros with a known signature. All others are blocked.',
                'Policy Score': 0,
            },
            'Control 2': {
                'Control Name': 'Microsoft Office macros in documents originating from the internet are blocked.',
                'Policy Name': 'Block Macros from running in Office files from the internet',
                'Policy Location': 'User Configuration > Administrative templates > Microsoft Word 2016 > Word options > Security Trust Center.',
                'Policy Script': None,
                'Policy Actions': 'Enable GPO to stop all office macros from running that originate from the web',
                'Policy Score': 0
            },
            'Control 3': {
                'Control Name': 'Microsoft Office macro security settings cannot be changed by users.',
                'Policy Name': 'Automation Security',
                'Policy Location': 'User Configuration\Policies\Administration Templates\Microsoft Office 2012\Security Settings',
                'Policy Script': None,
                'Policy Actions': 'Configure Automation Security to ensure that users are unbale to change macro security settings, helps to stop privilage escilation attacks',
                'Policy Score': 0
            }
        },
        'Maturity Level 3': {
            'Control 1': {
                'Control Name': 'Microsoft Office macros are only allowed to execute in documents from Trusted Locations where write access is limited to personnel whose role is to vet and approve macros.',
                'Policy Name': 'Allow mix of policy and user locations',
                'Policy Location': 'User Configuration\Policies\Administration Templates\Microsoft Office 2016\Security Settings\Trust Center',
                'Policy Script': None,
                'Policy Actions': 'Configure the policy to only run macros with a known signature. All others are blocked. Limit user access to read only.',
                'Policy Score': 0,
            },
            'Control 2': {
                'Control Name': 'Microsoft Office macros in documents originating from the internet are blocked.',
                'Policy Name': 'Block Macros from running in Office files from the internet',
                'Policy Location': 'User Configuration > Administrative templates > Microsoft Word 2016 > Word options > Security Trust Center.',
                'Policy Script': None,
                'Policy Actions': 'Enable GPO to stop all office macros from running that originate from the web',
                'Policy Score': 0
            },
            'Control 3': {
                'Control Name': 'Microsoft Office macro security settings cannot be changed by users.',
                'Policy Name': 'Automation Security',
                'Policy Location': 'User Configuration\Policies\Administration Templates\Microsoft Office 2012\Security Settings',
                'Policy Script': None,
                'Policy Actions': 'Configure Automation Security to ensure that users are unbale to change macro security settings, helps to stop privilage escilation attacks',
                'Policy Score': 0
            }
        }
    },
    'User Application Hardening': {
        'Maturity Level 1': {
            'Control 1': {
                'Control Name': 'Web browsers are configured to block or disable support for Flash content.',
                'Policy Name': 'Turn off Adobe Flash in Internet Explorer and prevent applications from using Internet Explorer technology to instantiate Flash objects',
                'Policy Location': 'Computer Configuration > Policies > Administrative Templates > Windows Components > Internet Explorer > Security Features > Add-on Management.',
                'Policy Script': None,
                'Policy Actions': 'Enable policy to disable flash content in the organisations browsers.',
                'Policy Score': 0
            }
        },
        'Maturity Level 2': {
            'Control 1': {
                'Control Name': 'Web browsers are configured to block or disable support for Flash content.',
                'Policy Name': 'Turn off Adobe Flash in Internet Explorer and prevent applications from using Internet Explorer technology to instantiate Flash objects',
                'Policy Location': 'Computer Configuration > Policies > Administrative Templates > Windows Components > Internet Explorer > Security Features > Add-on Management.',
                'Policy Script': None,
                'Policy Actions': 'Enable policy to disable flash content in the organisations browsers.',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Web browsers are configured to block web advertisements.',
                'Policy Name': 'Block popups',
                'Policy Location': 'Computer Configuration > Policies > Administrative Templates > Microsoft Office 2016 > IE Security',
                'Policy Script': None,
                'Policy Actions': 'Enable GPO to block ads from appearing in the organisations browers.',
                'Policy Score': 0
            },
            'Control 3': {
                'Control Name': 'Web browsers are configured to block Java from the internet.',
                'Policy Name': 'Disable Java',
                'Policy Location': 'Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Internet Control Panel > Security Page > Locked-Down Trusted Sites Zone',
                'Policy Script': None,
                'Policy Actions': 'Disable java through GPO.',
                'Policy Score': 0
            }
        },
        'Maturity Level 3': {
            'Control 1': {
                'Control Name': 'Web browsers are configured to block or disable support for Flash content.',
                'Policy Name': 'Turn off Adobe Flash in Internet Explorer and prevent applications from using Internet Explorer technology to instantiate Flash objects',
                'Policy Location': 'Computer Configuration > Policies > Administrative Templates > Windows Components > Internet Explorer > Security Features > Add-on Management.',
                'Policy Script': None,
                'Policy Actions': 'Enable policy to disable flash content in the organisations browsers.',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Web browsers are configured to block web advertisements.',
                'Policy Name': 'Block popups',
                'Policy Location': 'Computer Configuration > Policies > Administrative Templates > Microsoft Office 2016 > IE Security',
                'Policy Script': None,
                'Policy Actions': 'Enable GPO to block ads from appearing in the organisations browers.',
                'Policy Score': 0
            },
            'Control 3': {
                'Control Name': 'Web browsers are configured to block Java from the internet.',
                'Policy Name': 'Disable Java' ,
                'Policy Location': 'Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Internet Control Panel > Security Page > Locked-Down Trusted Sites Zone',
                'Policy Script': None,
                'Policy Actions': 'Disable java through GPO.',
                'Policy Score': 0
            },
            'Control 4': {
                'Control Name': 'Microsoft Office is configured to disable support for Flash content',
                'Policy Name': 'Block Flash activation in Office documents',
                'Policy Location': 'Computer Configuration > Policies > Administrative Templates > MS Security Guide',
                'Policy Script': None,
                'Policy Actions': 'Disable flash support for all office applications.',
                'Policy Score': 0
            },
            # 'Control 5': {
            #     'Control Name': ,
            #     'Policy Name': '',
            #     'Policy Location': ,
            #     'Policy Script': ,
            #     'Policy Actions': ,
            #     'Policy Score':
            # }
        }
    },
    'Restrict Administrative Privilages': {
        'Maturity Level 1': {
            'Control 1': {
                'Control Name': 'Privileged access to systems, applications and information is validated when first requested.',
                'Policy Name': 'Audit Sensitive Privilege Use',
                'Policy Location': 'Computer configuration > Policies > Windows Settings > Security Settings > Security Options',
                'Policy Script': None,
                'Policy Actions': 'Apply settings to ensure that passwords are required on all privileged actions',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Policy security controls are used to prevent privileged users from reading emails, browsing the web and obtaining files via online services.',
                'Policy Name': 'Audit Other Privilege Use Events',
                'Policy Location': 'Computer configuration > Policies > Windows Settings > Security Settings > Security Options',
                'Policy Script': None,
                'Policy Actions': 'Prevent admins from browsing the internet and performing everyday actions.',
                'Policy Score': 0
            }
        },
        'Maturity Level 2': {
            'Control 1': {
                'Control Name': 'Privileged access to systems, applications and information is validated when first requested.',
                'Policy Name': 'Audit Sensitive Privilege Use',
                'Policy Location': 'Computer configuration > Policies > Windows Settings > Security Settings > Security Options',
                'Policy Script': None,
                'Policy Actions': 'Apply settings to ensure that passwords are required on all privileged actions',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Policy security controls are used to prevent privileged users from reading emails, browsing the web and obtaining files via online services.',
                'Policy Name': 'Audit Other Privilege Use Events',
                'Policy Location': 'Computer configuration > Policies > Windows Settings > Security Settings > Security Options',
                'Policy Script': None,
                'Policy Actions': 'Prevent admins from browsing the internet and performing everyday actions.',
                'Policy Score': 0
            }
        },
        'Maturity Level 3': {
            'Control 1': {
                'Control Name': 'Privileged access to systems, applications and information is validated when first requested.',
                'Policy Name': 'Audit Sensitive Privilege Use',
                'Policy Location': 'Computer configuration > Policies > Windows Settings > Security Settings > Security Options',
                'Policy Script': None,
                'Policy Actions': 'Apply settings to ensure that passwords are required on all privileged actions',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Policy security controls are used to prevent privileged users from reading emails, browsing the web and obtaining files via online services.',
                'Policy Name': 'Audit Other Privilege Use Events',
                'Policy Location': 'Computer configuration > Policies > Windows Settings > Security Settings > Security Options',
                'Policy Script': None,
                'Policy Actions': 'Prevent admins from browsing the internet and performing everyday actions.',
                'Policy Score': 0
            },
            'Control 3': {
                'Control Name': 'Technical security controls are used to prevent privileged users from reading emails, browsing the web and obtaining files via online services',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'Get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Format-Table ProxyEnable',
                'Policy Actions': 'Implement a web proxy on users in privilaged groups so that they cant browse the internet',
                'Policy Score': 0
            }
        }
    },
    'Patch Operating Systems': {
        'Maturity Level 1': {
            'Control 1': {
                'Control Name': 'Security vulnerabilities in operating systems and firmware assessed as extreme risk are patched, updated or mitigated within one month of the security vulnerabilities being identified by vendors, independent third parties, system managers or users.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': '(Get-CimInstance Win32_OperatingSystem).version',
                'Policy Actions': 'Update the operating system to a newer version within the given timeframe.',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Operating systems for workstations, servers and ICT equipment that are no longer supported by vendors with patches or updates for security vulnerabilities are updated or replaced with vendorsupported versions.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'Get-ADComputer -Filter * -Property * | Format-Table Name,OperatingSystem,OperatingSystemVersion',
                'Policy Actions': 'Update all operating systems on devices within the network within the given timeframe directed by the software vendor.',
                'Policy Score': 0
            }
        },
        'Maturity Level 2': {
            'Control 1': {
                'Control Name': 'Security vulnerabilities in operating systems and firmware assessed as extreme risk are patched, updated or mitigated within one month of the security vulnerabilities being identified by vendors, independent third parties, system managers or users.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': '(Get-CimInstance Win32_OperatingSystem).version',
                'Policy Actions': 'Update the operating system to a newer version within the given timeframe.',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Operating systems for workstations, servers and ICT equipment that are no longer supported by vendors with patches or updates for security vulnerabilities are updated or replaced with vendorsupported versions.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'Get-ADComputer -Filter * -Property * | Format-Table Name,OperatingSystem,OperatingSystemVersion',
                'Policy Actions': 'Update all operating systems on devices within the network within the given timeframe directed by the software vendor.',
                'Policy Score': 0
            }
        },
        'Maturity Level 3': {
            'Control 1': {
                'Control Name': 'Security vulnerabilities in operating systems and firmware assessed as extreme risk are patched, updated or mitigated within one month of the security vulnerabilities being identified by vendors, independent third parties, system managers or users.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': '(Get-CimInstance Win32_OperatingSystem).version',
                'Policy Actions': 'Update the operating system to a newer version within the given timeframe.',
                'Policy Score': 0
            },
            # 'Control 2': {
            #     'Control Name': ,
            #     'Policy Name': '',
            #     'Policy Location': ,
            #     'Policy Script': ,
            #     'Policy Actions': ,
            #     'Policy Score':
            # },
            'Control 3': {
                'Control Name': 'Operating systems for workstations, servers and ICT equipment that are no longer supported by vendors with patches or updates for security vulnerabilities are updated or replaced with vendorsupported versions.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'Get-ADComputer -Filter * -Property * | Format-Table Name,OperatingSystem,OperatingSystemVersion',
                'Policy Actions': 'Update all operating systems on devices within the network within the given timeframe directed by the software vendor.',
                'Policy Score': 0
            }
        },
    },
    'Multi-factor Authentication': {
        'Maturity Level 1': {
            'Control 1': {
                'Control Name': 'Multi-factor authentication is used to authenticate all users of remote access solutions.',
                'Policy Name': 'Client: Limit Two Factor to RDP Logons Only',
                'Policy Location': 'Computer Policies > Policies > Adminstrative Templates > Duo Authentication > Client Settings',
                'Policy Script': None,
                'Policy Actions': 'Enable 2FA for all remote logons with the Duo Authentication GPOs.',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Multi-factor authentication uses at least two of the following authentication factors: passwords, Universal 2nd Factor security keys, physical one-time password tokens, biometrics, smartcards, mobile app one-time password tokens, SMS messages, emails, voice calls or software certificates.',
                'Policy Name': 'Client: Limit Two Factor to RDP Logons Only',
                'Policy Location': 'Computer Policies > Policies > Adminstrative Templates > Duo Authentication > Client Settings',
                'Policy Script': None,
                'Policy Actions': 'Add more of the authentication mechanisms discussed.',
                'Policy Score': 0
            }
        },
        'Maturity Level 2': {
            'Control 1': {
                'Control Name': 'Multi-factor authentication is used to authenticate all users of remote access solutions.',
                'Policy Name': 'Client: Limit Two Factor to RDP Logons Only',
                'Policy Location': 'Computer Policies > Policies > Adminstrative Templates > Duo Authentication > Client Settings',
                'Policy Script': None,
                'Policy Actions': 'Enable 2FA for all remote logons with the Duo Authentication GPOs.',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Multi-factor authentication is used to authenticate all privileged users and any other positions of trust.',
                'Policy Name': 'Client: Limit Two Factor to RDP Logons Only',
                'Policy Location': 'Computer Policies > Policies > Adminstrative Templates > Duo Authentication > Client Settings',
                'Policy Script': None,
                'Policy Actions': 'Enable 2FA for all actions that require higher level of security.',
                'Policy Score': 0
            },
            'Control 3': {
                'Control Name': 'Multi-factor authentication uses at least two of the following authentication factors: passwords, Universal 2nd Factor security keys, physical one-time password tokens, biometrics, smartcards or mobile app one-time password tokens.',
                'Policy Name': 'Client: Limit Two Factor to RDP Logons Only',
                'Policy Location': 'Computer Policies > Policies > Adminstrative Templates > Duo Authentication > Client Settings',
                'Policy Script': None,
                'Policy Actions': 'Add more of the authentication mechanisms discussed.',
                'Policy Score': 0
            }
        },
        'Maturity Level 3': {
            'Control 1': {
                'Control Name': 'Multi-factor authentication is used to authenticate all users of remote access solutions.',
                'Policy Name': 'Client: Limit Two Factor to RDP Logons Only',
                'Policy Location': 'Computer Policies > Policies > Adminstrative Templates > Duo Authentication > Client Settings',
                'Policy Script': None,
                'Policy Actions': 'Enable 2FA for all remote logons with the Duo Authentication GPOs.',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Multi-factor authentication is used to authenticate all privileged users and any other positions of trust.',
                'Policy Name': 'Client: Limit Two Factor to RDP Logons Only',
                'Policy Location': 'Computer Policies > Policies > Adminstrative Templates > Duo Authentication > Client Settings',
                'Policy Script': None,
                'Policy Actions': 'Enable 2FA for all actions that require higher level of security.',
                'Policy Score': 0
            },
            'Control 3': {
                'Control Name': 'Multi-factor authentication is used to authenticate all users when accessing important data repositories.',
                'Policy Name': 'Client: Limit Two Factor to RDP Logons Only',
                'Policy Location': 'Computer Policies > Policies > Adminstrative Templates > Duo Authentication > Client Settings',
                'Policy Script': None,
                'Policy Actions': 'Apply 2FA also to accessing key data stores.',
                'Policy Score': 0
            },
            'Control 4': {
                'Control Name': 'Multi-factor authentication uses at least two of the following authentication factors: passwords, Universal 2nd Factor security keys, physical one-time password tokens, biometrics or smartcards.',
                'Policy Name': 'Client: Limit Two Factor to RDP Logons Only',
                'Policy Location': 'Computer Policies > Policies > Adminstrative Templates > Duo Authentication > Client Settings',
                'Policy Script': None,
                'Policy Actions': 'Add more of the authentication mechanisms discussed.',
                'Policy Score': 0
            }
        },
    },
    'Daily Backups': {
        'Maturity Level 1': {
            'Control 1': {
                'Control Name': 'Backups of important information, software and configuration settings are performed monthly.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'WBAdmin ENABLE BACKUP',
                'Policy Actions': 'Backups of important information, software and configuration settings are performed weekly. Use the following script WBAdmin ENABLE BACKUP -addtarget:<DRIVER LETTER:> -schedule:TIME -include:<DRIVER LETTERS/FOLDERS:>',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Backups are stored for between one to three months.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'WBAdmin GET VERSIONS',
                'Policy Actions': 'Ensure that backups are being stored for the given duration.',
                'Policy Score': 0
            },
            'Control 3': {
                'Control Name': 'Partial restoration of backups is tested on an annual or more frequent basis.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'Get-VM',
                'Policy Actions': 'Create test server vm and restore system state. Use the following command Create test server vm and restore system state. Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All',
                'Policy Score': 0
            }
        },
        'Maturity Level 2': {
            'Control 1': {
                'Control Name': 'Backups of important information, software and configuration settings are performed weekly.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'WBAdmin ENABLE BACKUP',
                'Policy Actions': 'Backups of important information, software and configuration settings are performed weekly. Use the following script WBAdmin ENABLE BACKUP -addtarget:<DRIVER LETTER:> -schedule:TIME -include:<DRIVER LETTERS/FOLDERS:>',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Backups are stored offline, or online but in a non-rewritable and non-erasable manner.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'WBAdmin GET VERSIONS',
                'Policy Actions': 'Ensure that backups are being saved offline as well.',
                'Policy Score': 0
            },
            'Control 3': {
                'Control Name': 'Backups are stored for between one to three months.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'WBAdmin GET VERSIONS',
                'Policy Actions': 'Ensure that backups are being stored for the given duration.',
                'Policy Score': 0
            },
            'Control 4': {
                'Control Name': 'Full restoration of backups is tested at least once',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'Get-VM',
                'Policy Actions': 'Create test server vm and fully restore system state.',
                'Policy Score': 0
            },
            'Control 5': {
                'Control Name': 'Partial restoration of backups is tested on a bi-annual or more frequent basis.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'Get-VM',
                'Policy Actions': 'Create test server vm and restore partial system state.',
                'Policy Score': 0
            }
        },
        'Maturity Level 3': {
            'Control 1': {
                'Control Name': 'Backups of important information, software and configuration settings are performed at least daily.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'WBAdmin ENABLE BACKUP',
                'Policy Actions': 'Backups of important information, software and configuration settings are performed weekly. Use the following script WBAdmin ENABLE BACKUP -addtarget:<DRIVER LETTER:> -schedule:TIME -include:<DRIVER LETTERS/FOLDERS:>',
                'Policy Score': 0
            },
            'Control 2': {
                'Control Name': 'Backups are stored offline, or online but in a non-rewritable and non-erasable manner.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'WBAdmin GET VERSIONS',
                'Policy Actions': 'Ensure that backups are being saved offline as well.',
                'Policy Score': 0
            },
            'Control 3': {
                'Control Name': 'Backups are stored for three months or greater',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'WBAdmin GET VERSIONS',
                'Policy Actions': 'Ensure that backups are being stored for the given duration.',
                'Policy Score': 0
            },
            'Control 4': {
                'Control Name': 'Full restoration of backups is tested at least once when initially implemented and each time fundamental information technology infrastructure changes occur',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'Get-VM',
                'Policy Actions': 'Create test server vm and restore partial system state with the given conditions satisfied.',
                'Policy Score': 0
            },
            'Control 5': {
                'Control Name': 'Partial restoration of backups is tested on a quarterly or more frequent basis.',
                'Policy Name': None,
                'Policy Location': None,
                'Policy Script': 'Get-VM',
                'Policy Actions': 'Create test server vm and restore partial system state within the given timeframe.',
                'Policy Score': 0
            }
        },
    }
}