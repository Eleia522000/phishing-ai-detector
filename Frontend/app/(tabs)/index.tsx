import { Ionicons } from "@expo/vector-icons";
import Constants from "expo-constants";
import { useEffect, useState } from "react";
import { useShareIntent } from "expo-share-intent";
import {
  ActivityIndicator,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";

type ScreenState = "input" | "loading" | "result" | "details";

type SenderAnalysis = {
  sender: string | null;
  findings: string[];
  score: number;
};

type MessageAnalysis = {
  wordingFindings?: string[];
  findings?: string[];
  wordingScore?: number;
  bertFindings?: string[];
  bertScore?: number;
  bertPhishingProbability?: number | null;
  modelInputType?: string;
};

type HostingOrigin = {
  ip?: string;
  country_code?: string;
  country?: string;
  region?: string;
  city?: string;
  org?: string;
} | null;

type UrlAnalysis = {
  url: string;
  domain: string;
  domainAgeDays: number | null;
  hostingOrigin: HostingOrigin;
  domainAgeScore: number;
  hostingOriginScore: number;
  brandDomainScore: number;
  urlStructureScore: number;
  domainAgeFindings: string[];
  hostingOriginFindings: string[];
  brandDomainFindings: string[];
  urlStructureFindings: string[];
  totalUrlScore: number;
};

type AnalysisResult = {
  status: "Safe" | "Suspicious" | "Phishing" | "Legitimate";
  riskLevel: "Low" | "Medium" | "High";
  riskScore: number;
  claimedBrand: string | null;
  senderAnalysis?: SenderAnalysis;
  messageAnalysis?: MessageAnalysis;
  urlAnalyses?: UrlAnalysis[];
  reasons?: string[];
};

function normalizeBaseUrl(rawUrl?: string): string {
  if (!rawUrl) return "";
  return rawUrl.endsWith("/") ? rawUrl.slice(0, -1) : rawUrl;
}

const ENV_BACKEND_BASE_URL =
  normalizeBaseUrl(process.env.EXPO_PUBLIC_BACKEND_URL) ||
  normalizeBaseUrl((Constants.expoConfig?.extra as any)?.backendUrl) ||
  "";

// Web/browser on your laptop
// Phone app uses .env
const BACKEND_BASE_URL =
  Platform.OS === "web" ? "http://localhost:5000" : ENV_BACKEND_BASE_URL;

const BACKEND_URL = `${BACKEND_BASE_URL}/analyze`;

export default function HomeScreen() {
  const [input, setInput] = useState("");
  const [screenState, setScreenState] = useState<ScreenState>("input");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [sharedMessageNotice, setSharedMessageNotice] = useState("");

  const { hasShareIntent, shareIntent, resetShareIntent } = useShareIntent();

  useEffect(() => {
    if (!hasShareIntent) return;

    const sharedText =
      shareIntent?.text ||
      shareIntent?.webUrl ||
      shareIntent?.files?.[0]?.path ||
      "";

    if (sharedText) {
      setInput(sharedText);
      setScreenState("input");
      setResult(null);
      setErrorMessage("");
      setSharedMessageNotice("Shared message received. Press Analyze to scan it.");
    }

    resetShareIntent();
  }, [hasShareIntent, shareIntent, resetShareIntent]);

  const handleAnalyze = async () => {
    if (!input.trim()) {
      setErrorMessage("Please enter a message before analyzing.");
      setResult(null);
      setScreenState("input");
      return;
    }

    if (!BACKEND_BASE_URL) {
      setErrorMessage("Backend URL is missing.");
      return;
    }

    setIsAnalyzing(true);

    try {
      setErrorMessage("");
      setSharedMessageNotice("");
      setScreenState("loading");

      let response: Response;

      if (Platform.OS === "web") {
        const params = new URLSearchParams({
          text: input,
          sender: "",
          claimedBrand: "",
        });

        response = await fetch(`${BACKEND_URL}?${params.toString()}`, {
          method: "GET",
        });
      } else {
        response = await fetch(BACKEND_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            text: input,
            sender: "",
            claimedBrand: "",
          }),
        });
      }

      const contentType = response.headers.get("content-type") || "";
      let data: any = null;

      if (contentType.includes("application/json")) {
        data = await response.json();
      } else {
        const text = await response.text();
        throw new Error(text || `Unexpected response (${response.status})`);
      }

      if (!response.ok) {
        throw new Error(
          data?.message || data?.error || "Analysis failed. Please try again."
        );
      }

      setResult(data);
      setScreenState("result");
    } catch (error: any) {
      console.error("Analyze error:", error);
      setErrorMessage(String(error?.message || error || "Unknown error"));
      setScreenState("input");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleClose = () => {
    setScreenState("input");
    setResult(null);
    setInput("");
    setErrorMessage("");
    setSharedMessageNotice("");
  };

  const getRiskTheme = (riskLevel: "Low" | "Medium" | "High") => {
    if (riskLevel === "High") {
      return {
        pillBackground: "#3A171B",
        pillBorder: "#7F1D1D",
        pillText: "#F8B4B4",
        barColor: "#DC2626",
        cardBorder: "#5C2328",
      };
    }

    if (riskLevel === "Medium") {
      return {
        pillBackground: "#3A2A18",
        pillBorder: "#9A6700",
        pillText: "#F6C65B",
        barColor: "#D97706",
        cardBorder: "#5D421D",
      };
    }

    return {
      pillBackground: "#163229",
      pillBorder: "#1F7A5C",
      pillText: "#8FE3C0",
      barColor: "#1F9D73",
      cardBorder: "#245240",
    };
  };

  const getStatusTheme = (status: AnalysisResult["status"]) => {
    if (status === "Suspicious" || status === "Phishing") {
      return {
        badgeBackground: "#3A2A18",
        badgeBorder: "#9A6700",
        badgeText: "#F6C65B",
        iconName: "warning",
      };
    }

    return {
      badgeBackground: "#163229",
      badgeBorder: "#1F7A5C",
      badgeText: "#8FE3C0",
      iconName: "checkmark-circle",
    };
  };

  const getRiskBarWidth = (riskScore: number): `${number}%` => {
    const safeScore = Math.max(0, Math.min(riskScore, 100));
    return `${safeScore}%`;
  };

  const getMessageDetails = () => {
    if (!result) return [];

    return [
      ...(result.messageAnalysis?.wordingFindings || []),
      ...(result.messageAnalysis?.bertFindings || []),
      ...(result.messageAnalysis?.findings || []),
      ...(result.senderAnalysis?.findings || []),
    ];
  };

  const getLinkDetails = () => {
    if (!result) return [];

    if (!result.urlAnalyses || result.urlAnalyses.length === 0) {
      return [
        "No URL found in the message, so URL-based checks were not applied.",
      ];
    }

    const items: string[] = [];

    result.urlAnalyses.forEach((urlItem, index) => {
      items.push(`URL ${index + 1}: ${urlItem.url}`);
      items.push(`Domain: ${urlItem.domain}`);

      (urlItem.domainAgeFindings || []).forEach((item) => items.push(item));
      (urlItem.hostingOriginFindings || []).forEach((item) => items.push(item));
      (urlItem.brandDomainFindings || []).forEach((item) => items.push(item));
      (urlItem.urlStructureFindings || []).forEach((item) => items.push(item));
    });

    return items;
  };

  if (screenState === "loading") {
    return (
      <View style={styles.loadingScreen}>
        <View style={styles.loadingCard}>
          <View style={styles.logoCircle}>
            <Ionicons name="shield-checkmark" size={30} color="#5FA89A" />
          </View>

          <Text style={styles.loadingTitle}>Analyzing message...</Text>

          <ActivityIndicator
            size="large"
            color="#5FA89A"
            style={{ marginVertical: 20 }}
          />

          <Text style={styles.loadingText}>
            Please wait while MsgGuard checks for phishing indicators
          </Text>
        </View>
      </View>
    );
  }

  if (screenState === "details" && result) {
    const statusTheme = getStatusTheme(result.status);
    const messageDetails = getMessageDetails();
    const linkDetails = getLinkDetails();

    return (
      <ScrollView contentContainerStyle={styles.resultScrollContent}>
        <View style={styles.resultScreen}>
          <View style={styles.resultCard}>
            <View style={styles.logoRow}>
              <View style={styles.logoCircleSmall}>
                <Ionicons name="shield-checkmark" size={20} color="#5FA89A" />
              </View>
              <Text style={styles.resultLogoText}>MsgGuard</Text>
            </View>

            <View style={styles.resultTopRow}>
              <Text style={styles.resultStatusTitle}>Detailed Analysis</Text>

              <View
                style={[
                  styles.statusBadge,
                  {
                    backgroundColor: statusTheme.badgeBackground,
                    borderColor: statusTheme.badgeBorder,
                  },
                ]}
              >
                <Ionicons
                  name={statusTheme.iconName as any}
                  size={14}
                  color={statusTheme.badgeText}
                />
                <Text
                  style={[
                    styles.statusBadgeText,
                    { color: statusTheme.badgeText },
                  ]}
                >
                  {result.status}
                </Text>
              </View>
            </View>

            <View style={styles.detailSection}>
              <Text style={styles.sectionTitle}>Message Analysis</Text>
              {messageDetails.map((item, index) => (
                <View key={`msg-${index}`} style={styles.detailRow}>
                  <Ionicons
                    name="checkmark-circle"
                    size={18}
                    color="#5FA89A"
                    style={styles.detailIcon}
                  />
                  <Text style={styles.detailText}>{item}</Text>
                </View>
              ))}
            </View>

            <View style={styles.detailSection}>
              <Text style={styles.sectionTitle}>Link Analysis</Text>
              {linkDetails.map((item, index) => (
                <View key={`link-${index}`} style={styles.detailRow}>
                  <Ionicons
                    name="checkmark-circle"
                    size={18}
                    color="#5FA89A"
                    style={styles.detailIcon}
                  />
                  <Text style={styles.detailText}>{item}</Text>
                </View>
              ))}
            </View>

            <Text style={styles.warningText}>
              Exercise caution and verify suspicious links before opening them.
            </Text>

            <TouchableOpacity style={styles.closeButton} onPress={handleClose}>
              <Text style={styles.closeButtonText}>Close</Text>
            </TouchableOpacity>
          </View>
        </View>
      </ScrollView>
    );
  }

  if (screenState === "result" && result) {
    const statusTheme = getStatusTheme(result.status);
    const riskTheme = getRiskTheme(result.riskLevel);

    return (
      <View style={styles.resultScreen}>
        <View style={styles.resultCard}>
          <View style={styles.logoRow}>
            <View style={styles.logoCircleSmall}>
              <Ionicons name="shield-checkmark" size={20} color="#5FA89A" />
            </View>
            <Text style={styles.resultLogoText}>MsgGuard</Text>
          </View>

          <View style={styles.resultTopRow}>
            <Text style={styles.resultStatusTitle}>MsgGuard</Text>

            <View
              style={[
                styles.statusBadge,
                {
                  backgroundColor: statusTheme.badgeBackground,
                  borderColor: statusTheme.badgeBorder,
                },
              ]}
            >
              <Ionicons
                name={statusTheme.iconName as any}
                size={14}
                color={statusTheme.badgeText}
              />
              <Text
                style={[
                  styles.statusBadgeText,
                  { color: statusTheme.badgeText },
                ]}
              >
                {result.status}
              </Text>
            </View>
          </View>

          <View
            style={[
              styles.riskIndicatorCard,
              { borderColor: riskTheme.cardBorder },
            ]}
          >
            <View style={styles.riskHeaderRow}>
              <Text style={styles.riskTitle}>Risk Overview</Text>
              <View
                style={[
                  styles.riskLevelPill,
                  {
                    backgroundColor: riskTheme.pillBackground,
                    borderColor: riskTheme.pillBorder,
                  },
                ]}
              >
                <Text
                  style={[
                    styles.riskLevelPillText,
                    { color: riskTheme.pillText },
                  ]}
                >
                  {result.riskLevel} Risk
                </Text>
              </View>
            </View>

            <Text style={styles.riskScoreText}>{result.riskScore}%</Text>

            <View style={styles.riskBarTrack}>
              <View
                style={[
                  styles.riskBarFill,
                  {
                    width: getRiskBarWidth(result.riskScore),
                    backgroundColor: riskTheme.barColor,
                  },
                ]}
              />
            </View>
          </View>

          <Text style={styles.reasonsHeading}>Top Reasons</Text>

          <View style={styles.reasonsContainer}>
            {(result.reasons || []).slice(0, 5).map((reason, index) => (
              <View key={index} style={styles.reasonRow}>
                <Text style={styles.reasonBullet}>•</Text>
                <Text style={styles.reasonText}>{reason}</Text>
              </View>
            ))}
          </View>

          <TouchableOpacity
            style={styles.detailsButton}
            onPress={() => setScreenState("details")}
          >
            <Text style={styles.detailsButtonText}>View Details</Text>
            <Ionicons name="chevron-forward" size={18} color="#D7E2DE" />
          </TouchableOpacity>

          <View style={styles.resultBottomSpacer} />

          <TouchableOpacity style={styles.closeButton} onPress={handleClose}>
            <Text style={styles.closeButtonText}>Close</Text>
          </TouchableOpacity>
        </View>
      </View>
    );
  }

  return (
    <ScrollView contentContainerStyle={styles.screen}>
      <View style={styles.container}>
        <View style={styles.logoRow}>
          <View style={styles.logoCircle}>
            <Ionicons name="shield-checkmark" size={26} color="#5FA89A" />
          </View>
          <Text style={styles.logoText}>MsgGuard</Text>
        </View>

        <Text style={styles.pageTitle}>Message Sharing and Analysis</Text>
        <Text style={styles.pageSubtitle}>
          Paste a message or URL, or share content directly from another app for phishing analysis.
        </Text>

        <View style={styles.card}>
          <Text style={styles.label}>Suspicious message or URL</Text>

          {sharedMessageNotice ? (
            <View style={styles.sharedNoticeBox}>
              <Ionicons name="share-social-outline" size={17} color="#8FE3C0" />
              <Text style={styles.sharedNoticeText}>{sharedMessageNotice}</Text>
            </View>
          ) : null}

          <TextInput
            style={styles.input}
            placeholder="Paste message text or URL here..."
            placeholderTextColor="#7E8B88"
            multiline
            value={input}
            onChangeText={(text) => {
              setInput(text);
              if (errorMessage) setErrorMessage("");
              if (sharedMessageNotice) setSharedMessageNotice("");
            }}
          />

          {errorMessage ? (
            <Text style={styles.errorText}>{errorMessage}</Text>
          ) : null}

          <TouchableOpacity
            style={[
              styles.analyzeButton,
              isAnalyzing && styles.analyzeButtonDisabled,
            ]}
            onPress={handleAnalyze}
            disabled={isAnalyzing}
          >
            <Ionicons name="search" size={18} color="#F4F7F6" />
            <Text style={styles.analyzeButtonText}>
              {isAnalyzing ? "Analyzing..." : "Analyze"}
            </Text>
          </TouchableOpacity>
        </View>

        <View style={styles.howItWorksCard}>
          <Text style={styles.howItWorksTitle}>How it works</Text>

          <View style={styles.howItWorksStep}>
            <View style={styles.stepNumber}>
              <Text style={styles.stepNumberText}>1</Text>
            </View>
            <Text style={styles.howItWorksText}>
              Submit a message or URL
            </Text>
          </View>

          <View style={styles.howItWorksStep}>
            <View style={styles.stepNumber}>
              <Text style={styles.stepNumberText}>2</Text>
            </View>
            <Text style={styles.howItWorksText}>
              MsgGuard checks message content, URLs, and website identity
            </Text>
          </View>

          <View style={styles.howItWorksStepLast}>
            <View style={styles.stepNumber}>
              <Text style={styles.stepNumberText}>3</Text>
            </View>
            <Text style={styles.howItWorksText}>
              Receive a risk score and threat explanation
            </Text>
          </View>
        </View>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  screen: {
    flexGrow: 1,
    backgroundColor: "#161C1B",
    justifyContent: "center",
    padding: 20,
  },
  container: {
    width: "100%",
    maxWidth: 520,
    alignSelf: "center",
  },
  logoRow: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    marginBottom: 18,
  },
  logoCircle: {
    width: 48,
    height: 48,
    borderRadius: 24,
    backgroundColor: "#222B2A",
    justifyContent: "center",
    alignItems: "center",
    marginRight: 10,
    borderWidth: 1,
    borderColor: "#313A38",
  },
  logoCircleSmall: {
    width: 32,
    height: 32,
    borderRadius: 16,
    backgroundColor: "#222B2A",
    justifyContent: "center",
    alignItems: "center",
    marginRight: 8,
    borderWidth: 1,
    borderColor: "#313A38",
  },
  logoText: {
    fontSize: 30,
    fontWeight: "800",
    color: "#F1F4F3",
  },
  resultLogoText: {
    fontSize: 24,
    fontWeight: "800",
    color: "#F1F4F3",
  },
  pageTitle: {
    fontSize: 24,
    fontWeight: "800",
    color: "#F1F4F3",
    textAlign: "center",
    marginBottom: 8,
  },
  pageSubtitle: {
    fontSize: 15,
    color: "#9CA7A4",
    textAlign: "center",
    marginBottom: 24,
  },
  card: {
    backgroundColor: "#222B2A",
    borderRadius: 24,
    padding: 20,
    shadowColor: "#000",
    shadowOpacity: 0.22,
    shadowRadius: 16,
    shadowOffset: { width: 0, height: 6 },
    elevation: 5,
    marginBottom: 18,
    borderWidth: 1,
    borderColor: "#313A38",
  },
  label: {
    fontSize: 15,
    fontWeight: "700",
    color: "#DDE4E1",
    marginBottom: 10,
  },
  sharedNoticeBox: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#163229",
    borderColor: "#1F7A5C",
    borderWidth: 1,
    borderRadius: 14,
    padding: 10,
    marginBottom: 12,
    gap: 8,
  },
  sharedNoticeText: {
    flex: 1,
    color: "#8FE3C0",
    fontSize: 14,
    lineHeight: 19,
    fontWeight: "600",
  },
  input: {
    minHeight: 170,
    backgroundColor: "#181E1D",
    borderWidth: 1,
    borderColor: "#394240",
    borderRadius: 18,
    padding: 16,
    fontSize: 16,
    color: "#F1F4F3",
    textAlignVertical: "top",
    marginBottom: 12,
  },
  errorText: {
    color: "#FF6B6B",
    backgroundColor: "#3A171B",
    borderColor: "#7F1D1D",
    borderWidth: 1,
    borderRadius: 12,
    padding: 10,
    marginBottom: 12,
    fontSize: 14,
    lineHeight: 20,
    fontWeight: "700",
    textAlign: "center",
  },
  analyzeButton: {
    height: 52,
    borderRadius: 16,
    backgroundColor: "#4C7F75",
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
  },
  analyzeButtonDisabled: {
    opacity: 0.6,
  },
  analyzeButtonText: {
    color: "#F4F7F6",
    fontSize: 17,
    fontWeight: "800",
  },
  howItWorksCard: {
    backgroundColor: "#1E2927",
    borderRadius: 20,
    padding: 18,
    borderWidth: 1,
    borderColor: "#32413E",
  },
  howItWorksTitle: {
    fontSize: 17,
    fontWeight: "800",
    color: "#F1F4F3",
    marginBottom: 14,
  },
  howItWorksStep: {
    flexDirection: "row",
    alignItems: "center",
    marginBottom: 12,
  },
  howItWorksStepLast: {
    flexDirection: "row",
    alignItems: "center",
  },
  stepNumber: {
    width: 26,
    height: 26,
    borderRadius: 13,
    backgroundColor: "#4C7F75",
    justifyContent: "center",
    alignItems: "center",
    marginRight: 10,
  },
  stepNumberText: {
    color: "#F4F7F6",
    fontSize: 13,
    fontWeight: "800",
  },
  howItWorksText: {
    flex: 1,
    color: "#C9D4D1",
    fontSize: 15,
    lineHeight: 21,
  },
  loadingScreen: {
    flex: 1,
    backgroundColor: "#161C1B",
    justifyContent: "center",
    alignItems: "center",
    padding: 20,
  },
  loadingCard: {
    width: "100%",
    maxWidth: 420,
    backgroundColor: "#222B2A",
    borderRadius: 24,
    padding: 30,
    alignItems: "center",
    shadowColor: "#000",
    shadowOpacity: 0.22,
    shadowRadius: 16,
    shadowOffset: { width: 0, height: 6 },
    borderWidth: 1,
    borderColor: "#313A38",
  },
  loadingTitle: {
    fontSize: 20,
    fontWeight: "800",
    color: "#F1F4F3",
    marginTop: 16,
  },
  loadingText: {
    fontSize: 15,
    color: "#9CA7A4",
    textAlign: "center",
  },
  resultScrollContent: {
    flexGrow: 1,
    backgroundColor: "#161C1B",
    padding: 20,
  },
  resultScreen: {
    flex: 1,
    backgroundColor: "#161C1B",
    justifyContent: "center",
    alignItems: "center",
    padding: 20,
  },
  resultCard: {
    width: "100%",
    maxWidth: 420,
    minHeight: 620,
    backgroundColor: "#222B2A",
    borderRadius: 24,
    padding: 24,
    shadowColor: "#000",
    shadowOpacity: 0.22,
    shadowRadius: 16,
    shadowOffset: { width: 0, height: 6 },
    borderWidth: 1,
    borderColor: "#313A38",
  },
  resultTopRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 18,
    marginTop: 6,
  },
  resultStatusTitle: {
    fontSize: 18,
    fontWeight: "700",
    color: "#F1F4F3",
  },
  statusBadge: {
    flexDirection: "row",
    alignItems: "center",
    gap: 5,
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 999,
    borderWidth: 1,
  },
  statusBadgeText: {
    fontSize: 13,
    fontWeight: "700",
  },
  riskIndicatorCard: {
    backgroundColor: "#181E1D",
    borderRadius: 18,
    padding: 16,
    marginBottom: 18,
    borderWidth: 1,
  },
  riskHeaderRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 10,
  },
  riskTitle: {
    fontSize: 16,
    fontWeight: "800",
    color: "#F1F4F3",
  },
  riskLevelPill: {
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 999,
    borderWidth: 1,
  },
  riskLevelPillText: {
    fontSize: 13,
    fontWeight: "800",
  },
  riskScoreText: {
    fontSize: 30,
    fontWeight: "800",
    color: "#F1F4F3",
    marginBottom: 12,
  },
  riskBarTrack: {
    height: 10,
    backgroundColor: "#2D3634",
    borderRadius: 999,
    overflow: "hidden",
  },
  riskBarFill: {
    height: "100%",
    borderRadius: 999,
  },
  reasonsHeading: {
    fontSize: 18,
    fontWeight: "800",
    color: "#F1F4F3",
    marginTop: 4,
    marginBottom: 12,
  },
  reasonsContainer: {
    marginBottom: 18,
  },
  reasonRow: {
    flexDirection: "row",
    marginBottom: 10,
    alignItems: "flex-start",
  },
  reasonBullet: {
    fontSize: 18,
    color: "#5FA89A",
    marginRight: 8,
    lineHeight: 22,
  },
  reasonText: {
    flex: 1,
    fontSize: 15,
    color: "#D1D8D5",
    lineHeight: 22,
  },
  detailsButton: {
    height: 48,
    borderRadius: 999,
    backgroundColor: "#2C3533",
    justifyContent: "center",
    alignItems: "center",
    flexDirection: "row",
    gap: 6,
    borderWidth: 1,
    borderColor: "#3A4441",
  },
  detailsButtonText: {
    color: "#D7E2DE",
    fontSize: 16,
    fontWeight: "700",
  },
  resultBottomSpacer: {
    height: 56,
  },
  closeButton: {
    marginTop: 6,
    height: 48,
    borderRadius: 999,
    backgroundColor: "#4C7F75",
    justifyContent: "center",
    alignItems: "center",
  },
  closeButtonText: {
    color: "#F4F7F6",
    fontSize: 16,
    fontWeight: "800",
  },
  detailSection: {
    marginTop: 10,
    marginBottom: 8,
    padding: 14,
    backgroundColor: "#181E1D",
    borderRadius: 16,
    borderWidth: 1,
    borderColor: "#394240",
  },
  sectionTitle: {
    fontSize: 17,
    fontWeight: "800",
    color: "#F1F4F3",
    marginBottom: 10,
  },
  detailRow: {
    flexDirection: "row",
    alignItems: "flex-start",
    marginBottom: 10,
  },
  detailIcon: {
    marginRight: 8,
    marginTop: 2,
  },
  detailText: {
    flex: 1,
    fontSize: 15,
    color: "#D1D8D5",
    lineHeight: 22,
  },
  warningText: {
    fontSize: 14,
    color: "#9CA7A4",
    textAlign: "center",
    marginTop: 14,
    lineHeight: 20,
  },
});
