import SwiftUI

let fortressBackground = Color(red: 246 / 255, green: 247 / 255, blue: 249 / 255)
let fortressSurface = Color(red: 255 / 255, green: 255 / 255, blue: 255 / 255)
let fortressSidebar = Color(red: 17 / 255, green: 19 / 255, blue: 24 / 255)
let fortressSidebarText = Color(red: 248 / 255, green: 248 / 255, blue: 250 / 255)
let fortressSidebarMuted = Color(red: 166 / 255, green: 172 / 255, blue: 185 / 255)
let fortressAccent = Color(red: 82 / 255, green: 82 / 255, blue: 204 / 255)
let fortressAccentSoft = Color(red: 238 / 255, green: 238 / 255, blue: 255 / 255)
let fortressAccentBorder = Color(red: 202 / 255, green: 202 / 255, blue: 241 / 255)
let fortressText = Color(red: 29 / 255, green: 34 / 255, blue: 44 / 255)
let fortressMutedText = Color(red: 91 / 255, green: 99 / 255, blue: 115 / 255)
let fortressBorder = Color(red: 222 / 255, green: 225 / 255, blue: 232 / 255)
let fortressSuccess = Color(red: 23 / 255, green: 123 / 255, blue: 82 / 255)
let fortressError = Color(red: 185 / 255, green: 52 / 255, blue: 68 / 255)
let fortressWarning = Color(red: 166 / 255, green: 91 / 255, blue: 28 / 255)
private let fortressFormLabelWidth: CGFloat = 164
private let fortressFieldHeight: CGFloat = 32

struct FortressLogoView: View {
  var body: some View {
    Canvas { context, size in
      let scaleX = size.width / 40
      let scaleY = size.height / 40
      func rect(_ x: CGFloat, _ y: CGFloat, _ width: CGFloat, _ height: CGFloat) -> CGRect {
        CGRect(x: x * scaleX, y: y * scaleY, width: width * scaleX, height: height * scaleY)
      }
      let shell = Path(
        roundedRect: CGRect(origin: .zero, size: size),
        cornerRadius: 11 * min(scaleX, scaleY))
      context.fill(shell, with: .color(Color(red: 27 / 255, green: 28 / 255, blue: 36 / 255)))
      context.stroke(
        shell, with: .color(Color(red: 75 / 255, green: 75 / 255, blue: 111 / 255)),
        lineWidth: max(1, scaleX))

      let violet = Color(red: 132 / 255, green: 132 / 255, blue: 242 / 255)
      let mint = Color(red: 239 / 255, green: 239 / 255, blue: 255 / 255)
      let ink = Color(red: 20 / 255, green: 20 / 255, blue: 30 / 255)
      var fortress = Path()
      fortress.move(to: CGPoint(x: 5 * scaleX, y: 34 * scaleY))
      for point in [
        CGPoint(x: 5, y: 7), CGPoint(x: 9, y: 7), CGPoint(x: 9, y: 12),
        CGPoint(x: 12, y: 12), CGPoint(x: 12, y: 7), CGPoint(x: 16, y: 7),
        CGPoint(x: 16, y: 15), CGPoint(x: 24, y: 15), CGPoint(x: 24, y: 7),
        CGPoint(x: 28, y: 7), CGPoint(x: 28, y: 12), CGPoint(x: 31, y: 12),
        CGPoint(x: 31, y: 7), CGPoint(x: 35, y: 7), CGPoint(x: 35, y: 34),
      ] {
        fortress.addLine(to: CGPoint(x: point.x * scaleX, y: point.y * scaleY))
      }
      fortress.closeSubpath()
      context.fill(fortress, with: .color(violet))
      context.stroke(fortress, with: .color(mint), lineWidth: max(1, 1.1 * scaleX))

      for row in 0..<4 {
        for column in 0..<3 {
          context.fill(
            Path(roundedRect: rect(8 + CGFloat(column) * 3.3, 19 + CGFloat(row) * 3.1, 1.8, 0.9), cornerRadius: 0.45),
            with: .color(mint))
          context.fill(
            Path(roundedRect: rect(25 + CGFloat(column) * 3.3, 19 + CGFloat(row) * 3.1, 1.8, 0.9), cornerRadius: 0.45),
            with: .color(mint))
        }
      }
      let gate = Path(roundedRect: rect(16.5, 18.5, 7, 15.5), cornerRadius: 3.5 * scaleX)
      context.fill(gate, with: .color(ink))
      context.stroke(gate, with: .color(mint), lineWidth: max(1, scaleX))
      var seed = Path()
      seed.move(to: CGPoint(x: 20 * scaleX, y: 21 * scaleY))
      seed.addLine(to: CGPoint(x: 22.8 * scaleX, y: 26.5 * scaleY))
      seed.addLine(to: CGPoint(x: 20 * scaleX, y: 32 * scaleY))
      seed.addLine(to: CGPoint(x: 17.2 * scaleX, y: 26.5 * scaleY))
      seed.closeSubpath()
      context.fill(seed, with: .color(mint))
      var base = Path()
      base.move(to: CGPoint(x: 4 * scaleX, y: 34 * scaleY))
      base.addLine(to: CGPoint(x: 36 * scaleX, y: 34 * scaleY))
      context.stroke(base, with: .color(mint), lineWidth: max(1.4, 1.8 * scaleX))
    }
    .frame(width: 40, height: 40)
  }
}

struct FortressCard<Content: View>: View {
  let content: Content

  init(@ViewBuilder content: () -> Content) {
    self.content = content()
  }

  var body: some View {
    content
      .padding(20)
      .frame(maxWidth: .infinity, alignment: .leading)
      .background(fortressSurface)
      .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
      .overlay(
        RoundedRectangle(cornerRadius: 14, style: .continuous)
          .stroke(fortressBorder, lineWidth: 1)
      )
  }
}

struct PageHeading: View {
  let title: String
  let subtitle: String

  var body: some View {
    VStack(alignment: .leading, spacing: 7) {
      Text(title)
        .font(.system(size: 28, weight: .bold, design: .rounded))
        .foregroundColor(fortressText)
      Text(subtitle)
        .font(.system(size: 15))
        .foregroundColor(fortressMutedText)
        .fixedSize(horizontal: false, vertical: true)
    }
  }
}

struct SectionHeading: View {
  let symbol: String
  let title: String
  let subtitle: String?

  init(_ title: String, symbol: String, subtitle: String? = nil) {
    self.title = title
    self.symbol = symbol
    self.subtitle = subtitle
  }

  var body: some View {
    HStack(alignment: .top, spacing: 13) {
      Image(systemName: symbol)
        .font(.system(size: 15, weight: .semibold))
        .foregroundColor(fortressAccent)
        .frame(width: 34, height: 34)
        .background(fortressAccentSoft)
        .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
      VStack(alignment: .leading, spacing: 4) {
        Text(title)
          .font(.system(size: 18, weight: .bold, design: .rounded))
        if let subtitle {
          Text(subtitle)
            .font(.system(size: 14))
            .foregroundColor(fortressMutedText)
            .fixedSize(horizontal: false, vertical: true)
        }
      }
    }
  }
}

struct FortressCallout: View {
  let symbol: String
  let title: String
  let message: String
  var warning = false

  var body: some View {
    HStack(alignment: .top, spacing: 13) {
      Image(systemName: symbol)
        .font(.system(size: 16, weight: .semibold))
        .foregroundColor(warning ? fortressWarning : fortressAccent)
        .padding(.top, 1)
      VStack(alignment: .leading, spacing: 5) {
        Text(title).font(.system(size: 14, weight: .semibold))
        Text(message)
          .font(.system(size: 13.5))
          .foregroundColor(fortressMutedText)
          .fixedSize(horizontal: false, vertical: true)
      }
    }
    .padding(16)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background((warning ? fortressWarning : fortressAccentSoft).opacity(warning ? 0.08 : 1))
    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
    .overlay(
      RoundedRectangle(cornerRadius: 12, style: .continuous)
        .stroke(warning ? fortressWarning.opacity(0.30) : fortressAccentBorder, lineWidth: 1)
    )
  }
}

struct StatusBanner: View {
  let message: String
  let isError: Bool

  var body: some View {
    HStack(alignment: .top, spacing: 10) {
      Image(systemName: isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
        .foregroundColor(isError ? fortressError : fortressSuccess)
      Text(message)
        .font(.system(size: 13.5, weight: .medium))
        .textSelection(.enabled)
        .fixedSize(horizontal: false, vertical: true)
      Spacer(minLength: 0)
    }
    .padding(13)
    .background((isError ? fortressError : fortressSuccess).opacity(0.07))
    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
  }
}

struct MnemonicWordsView: View {
  let phrase: String
  let revealed: Bool

  private var words: [String] {
    phrase.split(whereSeparator: { $0.isWhitespace }).map(String.init)
  }

  var body: some View {
    if words.isEmpty {
      Text("—")
        .foregroundColor(fortressMutedText)
        .frame(maxWidth: .infinity, minHeight: 54, alignment: .center)
    } else {
      LazyVGrid(columns: [GridItem(.adaptive(minimum: 132), spacing: 8)], spacing: 8) {
        ForEach(Array(words.enumerated()), id: \.offset) { index, word in
          HStack(spacing: 9) {
            Text(String(format: "%02d", index + 1))
              .font(.system(size: 11, weight: .medium, design: .monospaced))
              .foregroundColor(fortressMutedText)
            Text(revealed ? word : "••••")
              .font(.system(size: 13.5, weight: .medium, design: .monospaced))
              .lineLimit(1)
            Spacer(minLength: 0)
          }
          .padding(.horizontal, 10)
          .frame(height: 38)
          .background(Color(red: 248 / 255, green: 249 / 255, blue: 251 / 255))
          .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
          .overlay(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
              .stroke(fortressBorder, lineWidth: 1)
          )
        }
      }
    }
  }
}

struct FormRow<Content: View>: View {
  let label: String
  let content: Content

  init(_ label: String, @ViewBuilder content: () -> Content) {
    self.label = label
    self.content = content()
  }

  var body: some View {
    HStack(alignment: .center, spacing: 14) {
      Text(label)
        .font(.system(size: 14, weight: .medium))
        .foregroundColor(fortressMutedText)
        .frame(width: fortressFormLabelWidth, alignment: .trailing)
        .fixedSize(horizontal: false, vertical: true)
      HStack(spacing: 10) {
        content
      }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
    .frame(maxWidth: .infinity, minHeight: fortressFieldHeight, alignment: .leading)
  }
}

struct FormBlock<Content: View>: View {
  let label: String
  let content: Content

  init(_ label: String, @ViewBuilder content: () -> Content) {
    self.label = label
    self.content = content()
  }

  var body: some View {
    HStack(alignment: .top, spacing: 14) {
      Text(label)
        .font(.system(size: 14, weight: .medium))
        .foregroundColor(fortressMutedText)
        .frame(width: fortressFormLabelWidth, alignment: .trailing)
        .padding(.top, 7)
        .fixedSize(horizontal: false, vertical: true)
      VStack(alignment: .leading, spacing: 9) {
        content
      }
      .frame(maxWidth: .infinity, alignment: .leading)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}

struct FormActions<Content: View>: View {
  let content: Content

  init(@ViewBuilder content: () -> Content) {
    self.content = content()
  }

  var body: some View {
    HStack(alignment: .center, spacing: 14) {
      Color.clear.frame(width: fortressFormLabelWidth, height: 1)
      HStack(spacing: 10) {
        content
      }
      .frame(maxWidth: .infinity, alignment: .leading)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}

struct BusyOverlay: View {
  let visible: Bool
  var body: some View {
    if visible {
      ZStack {
        Color.black.opacity(0.08)
        ProgressView()
          .controlSize(.large)
          .padding(24)
          .background(.regularMaterial)
          .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
      }
      .ignoresSafeArea()
    }
  }
}

extension View {
  func fortressField() -> some View {
    self
      .textFieldStyle(.roundedBorder)
      .controlSize(.large)
      .frame(minHeight: fortressFieldHeight)
  }

  func fortressPrimaryButton() -> some View {
    self.buttonStyle(.borderedProminent).tint(fortressAccent).controlSize(.large)
  }
}
