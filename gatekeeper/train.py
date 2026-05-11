# gatekeeper/train.py
import os
import numpy as np
from datasets import load_dataset
from transformers import (
    DistilBertTokenizer,
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments,
    EarlyStoppingCallback
)
from sklearn.metrics import classification_report, confusion_matrix
import torch

# ── PATHS ────────────────────────────────────────────────────
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODEL_DIR, exist_ok=True)


def compute_metrics(eval_pred):
    """Calculate accuracy, precision, recall, F1 for the injection class."""
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)

    accuracy = (predictions == labels).mean()
    tp = ((predictions == 1) & (labels == 1)).sum()
    fp = ((predictions == 1) & (labels == 0)).sum()
    fn = ((predictions == 0) & (labels == 1)).sum()

    precision = tp / (tp + fp + 1e-8)
    recall    = tp / (tp + fn + 1e-8)
    f1        = 2 * precision * recall / (precision + recall + 1e-8)

    return {
        "accuracy":  round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall":    round(float(recall), 4),
        "f1":        round(float(f1), 4),
    }


def train():
    print("=" * 60)
    print("  🛡️  GATEKEEPER TRAINING")
    print("  Model: DistilBERT")
    print("  Task: Prompt Injection Detection")
    print("=" * 60)

    # ── 1. DEVICE ──────────────────────────────────────────
    device = torch.device("mps" if torch.backends.mps.is_available()
                          else "cpu")
    print(f"\n  Device: {device}")

    # ── 2. LOAD DATASET ────────────────────────────────────
    print("\n  📥 Loading dataset...")
    ds = load_dataset("deepset/prompt-injections")
    print(f"  Train samples: {len(ds['train'])}")
    print(f"  Test samples:  {len(ds['test'])}")

    # ── 3. TOKENIZER ───────────────────────────────────────
    print("\n  🔤 Loading tokenizer...")
    tokenizer = DistilBertTokenizer.from_pretrained(
        "distilbert-base-uncased"
    )

    def tokenize(batch):
        return tokenizer(
            batch["text"],
            truncation=True,
            padding="max_length",
            max_length=128
        )

    print("  Tokenizing...")
    ds_tokenized = ds.map(tokenize, batched=True)
    ds_tokenized.set_format(
        type="torch",
        columns=["input_ids", "attention_mask", "label"]
    )

    # ── 4. MODEL ───────────────────────────────────────────
    print("\n  🧠 Loading DistilBERT...")
    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased",
        num_labels=2
    )
    model.to(device)

    # ── 5. TRAINING ARGS ───────────────────────────────────
    training_args = TrainingArguments(
        output_dir=os.path.join(MODEL_DIR, "checkpoints"),
        num_train_epochs=5,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        learning_rate=2e-5,
        warmup_steps=100,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        logging_steps=20,
        fp16=False,
    )

    # ── 6. TRAINER ─────────────────────────────────────────
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=ds_tokenized["train"],
        eval_dataset=ds_tokenized["test"],
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)]
    )

    # ── 7. TRAIN ───────────────────────────────────────────
    print("\n  🚀 Starting training...")
    print("  This will take ~10-20 minutes on Mac Intel CPU\n")
    trainer.train()

    # ── 8. EVALUATE ────────────────────────────────────────
    print("\n  📊 Final evaluation:")
    predictions_output = trainer.predict(ds_tokenized["test"])
    preds  = np.argmax(predictions_output.predictions, axis=-1)
    labels = predictions_output.label_ids

    print(classification_report(
        labels, preds,
        target_names=["Safe", "Injection"]
    ))

    cm = confusion_matrix(labels, preds)
    print("\n  Confusion Matrix:")
    print(f"               Predicted Safe   Predicted Injection")
    print(f"  Actual Safe       {cm[0][0]:>6}              {cm[0][1]:>6}")
    print(f"  Actual Injection  {cm[1][0]:>6}              {cm[1][1]:>6}")

    # ── 9. SAVE MODEL ──────────────────────────────────────
    final_path = os.path.join(MODEL_DIR, "distilbert_final")
    model.save_pretrained(final_path)
    tokenizer.save_pretrained(final_path)
    print(f"\n  💾 Model saved to: {final_path}")

    print("\n" + "=" * 60)
    print("  ✅ GATEKEEPER TRAINED")
    print("=" * 60)


if __name__ == "__main__":
    train()