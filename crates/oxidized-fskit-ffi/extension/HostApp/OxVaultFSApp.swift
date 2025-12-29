// OxVaultFSApp.swift
// Container app for the OxVault FSKit extension.
//
// This minimal app serves as the host for the FSKit extension.
// The extension is embedded in this app's bundle and activated
// through System Settings > General > Login Items & Extensions.

import SwiftUI

@main
struct OxVaultFSApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield")
                .font(.system(size: 64))
                .foregroundColor(.accentColor)

            Text("OxVault File System")
                .font(.largeTitle)
                .fontWeight(.bold)

            Text("Cryptomator Vault Support")
                .font(.title2)
                .foregroundColor(.secondary)

            Divider()
                .padding(.vertical)

            VStack(alignment: .leading, spacing: 12) {
                Label("Extension Status", systemImage: "gearshape.2")
                    .font(.headline)

                Text("To enable the OxVault file system extension:")
                    .foregroundColor(.secondary)

                VStack(alignment: .leading, spacing: 8) {
                    HStack(alignment: .top) {
                        Text("1.")
                            .fontWeight(.bold)
                        Text("Open System Settings")
                    }
                    HStack(alignment: .top) {
                        Text("2.")
                            .fontWeight(.bold)
                        Text("Go to General > Login Items & Extensions")
                    }
                    HStack(alignment: .top) {
                        Text("3.")
                            .fontWeight(.bold)
                        Text("Enable \"OxVault File System\" under File System Extensions")
                    }
                }
                .padding(.leading)
            }
            .padding()
            .background(Color.secondary.opacity(0.1))
            .cornerRadius(12)

            Spacer()

            Button("Open System Settings") {
                NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")!)
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(40)
        .frame(minWidth: 500, minHeight: 400)
    }
}
