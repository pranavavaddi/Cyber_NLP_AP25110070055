import java.awt.*;
import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;

/* ---------------------------------------------------------------
 *  Input wrapper
 * ------------------------------------------------------------- */
class ReportInput {
    static final String DEFAULT_ORIGIN = "Manual Input";

    final String content;
    final String origin;

    ReportInput(String content, String origin) {
        this.content = content;
        this.origin = origin;
    }

    ReportInput(String content) {
        this(content, DEFAULT_ORIGIN);
    }
}

/* ---------------------------------------------------------------
 *  Tokenizer (stand-alone, used through composition)
 * ------------------------------------------------------------- */
class Tokenizer {
    private static final Set<String> IGNORED = new HashSet<>(Arrays.asList(
        "the", "is", "a", "an", "and", "or", "of", "to", "in", "on", "for",
        "with", "by", "was", "were", "are", "be", "has", "have", "had",
        "this", "that", "from", "it", "as", "at", "their", "they"
    ));

    List<String> tokenize(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return Collections.emptyList();
        }

        String normalized = raw.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9\\s]", " ")
                .trim();

        if (normalized.isEmpty()) {
            return Collections.emptyList();
        }

        return Arrays.stream(normalized.split("\\s+"))
                .filter(token -> !IGNORED.contains(token))
                .collect(Collectors.toList());
    }
}

/* ---------------------------------------------------------------
 *  Multinomial Naive Bayes model with Laplace smoothing
 * ------------------------------------------------------------- */
class BayesModel {
    private static final String[][] TRAINING_SET = {
        {"Ransomware",
            "ransomware encrypt encrypted encryption files ransom payment "
          + "victim locked restore decrypt extortion"},
        {"Phishing",
            "phishing email emails password credentials fraudulent "
          + "malicious link fake login impersonation scam"},
        {"Malware",
            "malware trojan virus spyware infection malicious software "
          + "payload executable backdoor"},
        {"Data Breach",
            "data breach stolen leaked database information exposed "
          + "records exfiltration confidential"},
        {"Denial of Service",
            "denial service ddos dos traffic server network overload "
          + "requests unavailable flooding"},
        {"Credential Theft",
            "credential theft stolen username password authentication "
          + "account login keylogger identity"},
        {"Ransomware",
            "attackers encrypted documents demanded cryptocurrency "
          + "payment files inaccessible"},
        {"Phishing",
            "fraudulent message directed employees to fake website "
          + "steal credentials"}
    };

    private final Tokenizer tokenizer;
    private final Map<String, Map<String, Integer>> frequency = new HashMap<>();
    private final Map<String, Integer> tokensPerLabel = new HashMap<>();
    private final Map<String, Integer> samplesPerLabel = new HashMap<>();
    private final Set<String> knownTerms = new HashSet<>();
    private int sampleTotal = 0;

    BayesModel(Tokenizer tokenizer) {
        this.tokenizer = tokenizer;
        for (String[] row : TRAINING_SET) {
            learn(row[0], row[1]);
        }
    }

    private void learn(String label, String sample) {
        samplesPerLabel.merge(label, 1, Integer::sum);
        sampleTotal++;

        Map<String, Integer> bucket =
            frequency.computeIfAbsent(label, k -> new HashMap<>());

        for (String token : tokenizer.tokenize(sample)) {
            bucket.merge(token, 1, Integer::sum);
            tokensPerLabel.merge(label, 1, Integer::sum);
            knownTerms.add(token);
        }
    }

    String predict(String text) throws Exception {
        List<String> tokens = tokenizer.tokenize(text);

        if (tokens.isEmpty()) {
            throw new Exception("Please enter a valid cyber threat report.");
        }

        String winner = "Unknown";
        double top = Double.NEGATIVE_INFINITY;

        for (String label : frequency.keySet()) {
            double logScore = Math.log(
                (double) samplesPerLabel.get(label) / sampleTotal
            );

            Map<String, Integer> bucket = frequency.get(label);
            int denominator = tokensPerLabel.get(label) + knownTerms.size();

            for (String token : tokens) {
                int seen = bucket.getOrDefault(token, 0);
                logScore += Math.log((seen + 1.0) / denominator);
            }

            if (logScore > top) {
                top = logScore;
                winner = label;
            }
        }

        return winner;
    }

    List<String> topTerms(String text) {
        List<String> found = tokenizer.tokenize(text).stream()
                .filter(knownTerms::contains)
                .distinct()
                .limit(8)
                .collect(Collectors.toList());

        return found.isEmpty()
                ? Collections.singletonList("No known keywords found")
                : found;
    }
}

/* ---------------------------------------------------------------
 *  Result holder
 * ------------------------------------------------------------- */
class ScanOutcome {
    private static final DateTimeFormatter STAMP =
        DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");

    final String label;
    final List<String> terms;
    final String origin;
    final String stamp;

    ScanOutcome(String label, List<String> terms, String origin) {
        this.label = label;
        this.terms = terms;
        this.origin = origin;
        this.stamp = LocalDateTime.now().format(STAMP);
    }

    String termsAsText() {
        return String.join(", ", terms);
    }
}

/* ---------------------------------------------------------------
 *  Analysis service (wraps the model)
 * ------------------------------------------------------------- */
class ScanService {
    private final BayesModel model = new BayesModel(new Tokenizer());

    ScanOutcome scan(ReportInput input) throws Exception {
        if (input == null) {
            throw new Exception("Report cannot be null.");
        }
        String label = model.predict(input.content);
        List<String> terms = model.topTerms(input.content);
        return new ScanOutcome(label, terms, input.origin);
    }
}

/* ---------------------------------------------------------------
 *  History table + CSV export
 * ------------------------------------------------------------- */
class HistoryLog {
    private static final String[] COLUMNS =
        {"Date and Time", "Source", "Category", "Keywords"};

    private final DefaultTableModel tableModel;

    HistoryLog() {
        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
    }

    DefaultTableModel getTableModel() {
        return tableModel;
    }

    void record(ScanOutcome outcome) {
        tableModel.addRow(new Object[]{
            outcome.stamp, outcome.origin, outcome.label, outcome.termsAsText()
        });
    }

    void saveAsCsv(Component parent) {
        JFileChooser picker = new JFileChooser();
        picker.setSelectedFile(new File("classification_history.csv"));

        if (picker.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        try (PrintWriter out = new PrintWriter(
                new FileWriter(picker.getSelectedFile()))) {

            out.println("Date and Time,Source,Category,Keywords");

            for (int r = 0; r < tableModel.getRowCount(); r++) {
                final int row = r;
                out.println(
                    java.util.stream.IntStream.range(0, 4)
                        .mapToObj(c -> quote(tableModel.getValueAt(row, c)))
                        .collect(Collectors.joining(","))
                );
            }

            JOptionPane.showMessageDialog(parent,
                "History exported successfully.");

        } catch (IOException ex) {
            JOptionPane.showMessageDialog(parent,
                "Unable to export history: " + ex.getMessage(),
                "File Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static String quote(Object cell) {
        return "\"" + String.valueOf(cell).replace("\"", "\"\"") + "\"";
    }
}

/* ---------------------------------------------------------------
 *  Main window
 * ------------------------------------------------------------- */
class MainWindow extends JFrame {

    private static final Color BG = new Color(19, 27, 43);
    private static final Color PANEL = new Color(30, 41, 59);
    private static final Color ACCENT = new Color(56, 189, 248);
    private static final Color TEXT = new Color(235, 241, 250);

    private final ScanService service = new ScanService();
    private final HistoryLog history = new HistoryLog();

    private JTextArea inputBox;
    private JTextArea outputBox;
    private JLabel statusBar;
    private JButton runButton;

    private String activeOrigin = ReportInput.DEFAULT_ORIGIN;

    MainWindow() {
        setTitle("CyberThreat Intel | Threat Report Classifier");
        setSize(1050, 720);
        setMinimumSize(new Dimension(850, 600));
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel root = new JPanel(new BorderLayout(12, 12));
        root.setBackground(BG);
        root.setBorder(BorderFactory.createEmptyBorder(18, 18, 18, 18));

        root.add(createHeader(), BorderLayout.NORTH);
        root.add(createBody(), BorderLayout.CENTER);

        add(root);
    }

    /* ----- UI construction ----- */

    private JPanel createHeader() {
        JLabel title = new JLabel("CyberThreat Intel", SwingConstants.CENTER);
        title.setForeground(ACCENT);
        title.setFont(new Font("Arial", Font.BOLD, 28));

        JLabel tagline = new JLabel(
            "NLP-Based Classification of Cyber Threat Intelligence Reports",
            SwingConstants.CENTER);
        tagline.setForeground(TEXT);
        tagline.setFont(new Font("Arial", Font.PLAIN, 13));

        JPanel box = new JPanel(new GridLayout(2, 1, 4, 4));
        box.setBackground(BG);
        box.add(title);
        box.add(tagline);
        return box;
    }

    private JTextArea createArea(int rows, boolean editable) {
        JTextArea area = new JTextArea(rows, 50);
        area.setEditable(editable);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(new Font("Consolas", Font.PLAIN, 14));
        area.setBackground(PANEL);
        area.setForeground(TEXT);
        area.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        return area;
    }

    private JPanel createBody() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Analyze", createAnalyzeTab());
        tabs.addTab("History", createHistoryTab());

        statusBar = new JLabel("Ready");
        statusBar.setForeground(ACCENT);

        outputBox = createArea(5, false);
        JScrollPane outputPane = new JScrollPane(outputBox);
        outputPane.setBorder(
            BorderFactory.createTitledBorder("Analysis Results"));

        JPanel lower = new JPanel(new BorderLayout(10, 10));
        lower.setBackground(BG);
        lower.add(outputPane, BorderLayout.CENTER);
        lower.add(statusBar, BorderLayout.SOUTH);

        JPanel body = new JPanel(new BorderLayout(10, 10));
        body.setBackground(BG);
        body.add(tabs, BorderLayout.CENTER);
        body.add(lower, BorderLayout.SOUTH);
        return body;
    }

    private JPanel createAnalyzeTab() {
        inputBox = createArea(10, true);
        inputBox.setCaretColor(ACCENT);

        JScrollPane inputPane = new JScrollPane(inputBox);
        inputPane.setBorder(
            BorderFactory.createTitledBorder("Threat Report Input"));

        JButton openBtn = new JButton("Load Report");
        runButton = new JButton("Analyze Report");
        JButton resetBtn = new JButton("Clear");
        JButton saveBtn = new JButton("Export History");

        openBtn.setToolTipText("Open a text report file");
        runButton.setToolTipText("Classify the report");
        resetBtn.setToolTipText("Clear the input and results");

        openBtn.addActionListener(e -> onLoad());
        runButton.addActionListener(e -> onAnalyze());
        resetBtn.addActionListener(e -> onReset());
        saveBtn.addActionListener(e -> history.saveAsCsv(this));

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 10));
        bar.setBackground(BG);
        bar.add(openBtn);
        bar.add(runButton);
        bar.add(resetBtn);
        bar.add(saveBtn);

        JPanel tab = new JPanel(new BorderLayout(10, 10));
        tab.setBackground(BG);
        tab.add(inputPane, BorderLayout.CENTER);
        tab.add(bar, BorderLayout.SOUTH);
        return tab;
    }

    private JScrollPane createHistoryTab() {
        JTable table = new JTable(history.getTableModel());
        table.setRowHeight(24);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);

        JScrollPane pane = new JScrollPane(table);
        pane.setBorder(BorderFactory.createTitledBorder("Session History"));
        return pane;
    }

    /* ----- Event handlers ----- */

    private void onReset() {
        inputBox.setText("");
        outputBox.setText("");
        activeOrigin = ReportInput.DEFAULT_ORIGIN;
        statusBar.setText("Ready");
    }

    private void onLoad() {
        JFileChooser picker = new JFileChooser();
        picker.setDialogTitle("Select Cyber Threat Report");

        if (picker.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File chosen = picker.getSelectedFile();

        if (!chosen.getName().toLowerCase(Locale.ROOT).endsWith(".txt")) {
            JOptionPane.showMessageDialog(this, "Please select a .txt file.",
                "Invalid File", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try (BufferedReader in = new BufferedReader(new FileReader(chosen))) {
            String body = in.lines()
                    .map(line -> line + "\n")
                    .collect(Collectors.joining());

            inputBox.setText(body);
            activeOrigin = chosen.getName();
            statusBar.setText("Report loaded successfully.");

        } catch (IOException | UncheckedIOException ex) {
            JOptionPane.showMessageDialog(this,
                "Unable to read report: " + ex.getMessage(),
                "File Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onAnalyze() {
        final String snapshot = inputBox.getText();
        final String origin = activeOrigin;

        runButton.setEnabled(false);
        outputBox.setText("Analyzing report...");
        statusBar.setText("Processing in background...");

        new SwingWorker<ScanOutcome, Void>() {
            @Override
            protected ScanOutcome doInBackground() throws Exception {
                return service.scan(new ReportInput(snapshot, origin));
            }

            @Override
            protected void done() {
                try {
                    ScanOutcome outcome = get();

                    outputBox.setText(
                        "Predicted Threat Category: " + outcome.label
                        + "\n\nImportant Keywords: " + outcome.termsAsText()
                        + "\n\nSource: " + outcome.origin
                        + "\nAnalyzed At: " + outcome.stamp
                        + "\n\nNote: Prototype prediction; not a validated "
                        + "security assessment."
                    );

                    history.record(outcome);
                    statusBar.setText("Classification completed.");

                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    statusBar.setText("Analysis interrupted.");

                } catch (ExecutionException ex) {
                    Throwable cause = ex.getCause();
                    outputBox.setText(cause == null
                        ? "Unable to analyze the report."
                        : cause.getMessage());
                    statusBar.setText("Classification failed.");

                } finally {
                    runButton.setEnabled(true);
                }
            }
        }.execute();
    }
}

/* ---------------------------------------------------------------
 *  Entry point
 * ------------------------------------------------------------- */
public class Main2 {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(
                    UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ex) {
                System.out.println("Using default interface appearance.");
            }
            new MainWindow().setVisible(true);
        });
    }
}
