// ContentView.swift
// Minimal UI for the File Provider host application.

import FileProvider
import SwiftUI

struct ContentView: View {
    @State private var domains: [(identifier: String, displayName: String)] = []
    @State private var isLoading = true
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 20) {
            // Header
            HStack {
                Image(systemName: "lock.shield.fill")
                    .font(.largeTitle)
                    .foregroundColor(.accentColor)

                VStack(alignment: .leading) {
                    Text("OxCrypt File Provider")
                        .font(.title)
                        .fontWeight(.bold)
                    Text("Encrypted vault access via File Provider")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            }
            .padding()

            Divider()

            // Domain list
            if isLoading {
                ProgressView("Loading domains...")
                    .padding()
            } else if let error = errorMessage {
                VStack {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.largeTitle)
                        .foregroundColor(.orange)
                    Text(error)
                        .foregroundColor(.secondary)
                }
                .padding()
            } else if domains.isEmpty {
                VStack {
                    Image(systemName: "tray")
                        .font(.largeTitle)
                        .foregroundColor(.secondary)
                    Text("No vaults registered")
                        .font(.headline)
                    Text("Use the oxcrypt CLI to mount a vault:\noxcrypt mount --backend fileprovider <vault>")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding()
            } else {
                List {
                    ForEach(domains, id: \.identifier) { domain in
                        DomainRow(identifier: domain.identifier, displayName: domain.displayName) {
                            Task {
                                await unregisterDomain(domain.identifier)
                            }
                        }
                    }
                }
            }

            Spacer()

            // Footer
            HStack {
                Button(action: { Task { await refreshDomains() } }) {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }

                Spacer()

                Text("Mount vaults via CLI or Desktop app")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding()
        }
        .frame(minWidth: 400, minHeight: 300)
        .task {
            await refreshDomains()
        }
    }

    private func refreshDomains() async {
        isLoading = true
        errorMessage = nil

        do {
            domains = try await DomainManager.listDomains()
        } catch {
            errorMessage = error.localizedDescription
        }

        isLoading = false
    }

    private func unregisterDomain(_ identifier: String) async {
        do {
            try await DomainManager.unregisterDomain(identifier)
            await refreshDomains()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

// MARK: - Domain Row

struct DomainRow: View {
    let identifier: String
    let displayName: String
    let onRemove: () -> Void

    @State private var isHovering = false

    var body: some View {
        HStack {
            Image(systemName: "folder.fill")
                .foregroundColor(.accentColor)

            VStack(alignment: .leading) {
                Text(displayName)
                    .font(.headline)
                Text(identifier.prefix(20) + "...")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()

            if isHovering {
                Button(action: onRemove) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.red)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.vertical, 4)
        .onHover { hovering in
            isHovering = hovering
        }
    }
}

#Preview {
    ContentView()
}
